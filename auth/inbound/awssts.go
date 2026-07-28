package inbound

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hoophq/mcpproxy/inspect"
)

// PresignedHeader carries the caller's presigned sts:GetCallerIdentity URL.
const PresignedHeader = "X-Amz-Presigned-GetCallerIdentity"

// maxPresignedExpiry bounds the X-Amz-Expires the gateway will accept. A
// presigned GetCallerIdentity URL is a bearer credential for the caller's AWS
// identity: a 7-day URL (the SigV4 maximum) leaked from a log is a week-long
// impersonation window, so anything beyond 15 minutes is refused.
const maxPresignedExpiry = 15 * time.Minute

// AWSSTSOptions configures AWS identity verification.
type AWSSTSOptions struct {
	// RoleMappings maps a glob pattern over the caller's ARN to a subject
	// template. A request whose ARN matches no pattern is rejected: an
	// unmapped AWS principal is an unknown principal.
	//
	// Templates may reference {arn}, {account}, {role}, {session},
	// {partition}, and {service}.
	RoleMappings map[string]string
	// Endpoint overrides where the gateway sends the presigned request. The
	// allowlist still runs against the URL the caller presented, so this
	// redirects only the network hop (tests point it at an httptest server).
	Endpoint string
	// HTTPClient overrides the client used to execute the presigned request.
	HTTPClient *http.Client
	// Now overrides the clock for expiry checks.
	Now func() time.Time
}

// callerIdentity is the subset of the STS GetCallerIdentity XML response the
// gateway needs. The field names match the AWS Query-protocol element names.
type callerIdentity struct {
	XMLName xml.Name `xml:"GetCallerIdentityResponse"`
	Arn     string   `xml:"GetCallerIdentityResult>Arn"`
	UserID  string   `xml:"GetCallerIdentityResult>UserId"`
	Account string   `xml:"GetCallerIdentityResult>Account"`
}

// arnParts is a parsed AWS ARN plus the assumed-role details the subject
// templates expose.
type arnParts struct {
	full      string
	partition string
	service   string
	account   string
	role      string
	session   string
}

// roleMapping is one compiled pattern→template pair.
type roleMapping struct {
	pattern  string
	template string
}

// AWSSTS authenticates a caller by replaying the presigned
// sts:GetCallerIdentity URL they sent in PresignedHeader.
//
// Only a holder of the AWS credentials can produce a valid SigV4 signature
// over that URL, and STS answers it with the signer's own ARN. The gateway
// needs no AWS credentials of its own and performs no role assumption: it
// asks AWS "who signed this?" and trusts the answer.
//
// The gateway checks the URL's host against the STS allowlist *before*
// sending the request, so a caller cannot turn this into an SSRF primitive
// by presigning a URL that points at an internal service.
func AWSSTS(opts AWSSTSOptions) (Resolver, error) {
	if len(opts.RoleMappings) == 0 {
		return nil, fmt.Errorf("inbound awssts: at least one aws_role_mappings entry is required")
	}
	mappings, err := compileRoleMappings(opts.RoleMappings)
	if err != nil {
		return nil, err
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	endpoint := strings.TrimSuffix(opts.Endpoint, "/")

	return func(r *http.Request) (inspect.Identity, error) {
		raw := r.Header.Get(PresignedHeader)
		if raw == "" {
			return inspect.Identity{}, fmt.Errorf("%w: missing %s header", ErrUnauthenticated, PresignedHeader)
		}
		u, err := validatePresigned(raw, now())
		if err != nil {
			return inspect.Identity{}, err
		}

		ident, err := callSTS(r, client, u, endpoint)
		if err != nil {
			return inspect.Identity{}, err
		}
		parts, err := parseARN(ident.Arn)
		if err != nil {
			return inspect.Identity{}, err
		}
		subject, pattern, ok := applyMappings(mappings, parts)
		if !ok {
			return inspect.Identity{}, fmt.Errorf(
				"%w: AWS principal %q matches no configured role mapping", ErrUnauthenticated, parts.full)
		}

		return inspect.Identity{
			Subject: subject,
			Claims: map[string]any{
				"provider":  "awssts",
				"arn":       parts.full,
				"account":   ident.Account,
				"user_id":   ident.UserID,
				"role":      parts.role,
				"session":   parts.session,
				"partition": parts.partition,
				"mapping":   pattern,
			},
		}, nil
	}, nil
}

// validatePresigned parses the caller-supplied URL and refuses anything that is
// not a fresh, https, signed GetCallerIdentity call to a real STS endpoint.
// now is the reference time for the staleness check.
func validatePresigned(raw string, now time.Time) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed presigned URL: %v", ErrUnauthenticated, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%w: presigned URL must use https, got %q", ErrUnauthenticated, u.Scheme)
	}
	if !isSTSHost(u.Hostname()) {
		return nil, fmt.Errorf("%w: %q is not an AWS STS endpoint", ErrUnauthenticated, u.Hostname())
	}

	q := u.Query()
	if q.Get("Action") != "GetCallerIdentity" {
		return nil, fmt.Errorf("%w: presigned URL must call GetCallerIdentity, got %q",
			ErrUnauthenticated, q.Get("Action"))
	}
	if q.Get("X-Amz-Signature") == "" || q.Get("X-Amz-Credential") == "" {
		return nil, fmt.Errorf("%w: presigned URL is not SigV4-signed", ErrUnauthenticated)
	}
	if err := checkFreshness(q.Get("X-Amz-Date"), q.Get("X-Amz-Expires"), now); err != nil {
		return nil, err
	}
	return u, nil
}

// checkFreshness enforces the presigned URL's lifetime in the gateway.
//
// AWS rejects an expired signature too, so this check is redundant for that
// case. It still earns its keep: it rejects a stale credential without
// spending a network round trip, and it caps the lifetime at
// maxPresignedExpiry, which AWS lets reach seven days.
//
// The gateway tolerates an absent X-Amz-Date: SigV4 allows the timestamp to
// travel in a signed Date header instead, and AWS remains the authority on
// the signature.
func checkFreshness(amzDate, amzExpires string, now time.Time) error {
	if amzExpires == "" {
		return nil
	}
	secs, err := strconv.Atoi(amzExpires)
	if err != nil || secs <= 0 {
		return fmt.Errorf("%w: invalid X-Amz-Expires %q", ErrUnauthenticated, amzExpires)
	}
	lifetime := time.Duration(secs) * time.Second
	if lifetime > maxPresignedExpiry {
		return fmt.Errorf("%w: presigned URL lifetime %s exceeds the %s maximum",
			ErrUnauthenticated, lifetime, maxPresignedExpiry)
	}
	if amzDate == "" {
		return nil
	}
	signedAt, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return fmt.Errorf("%w: invalid X-Amz-Date %q", ErrUnauthenticated, amzDate)
	}
	// clockSkew absorbs disagreement between the caller's clock and ours, the
	// same allowance AWS grants for SigV4 timestamps.
	const clockSkew = 5 * time.Minute
	if now.After(signedAt.Add(lifetime + clockSkew)) {
		return fmt.Errorf("%w: presigned URL expired at %s", ErrUnauthenticated, signedAt.Add(lifetime).UTC())
	}
	if now.Before(signedAt.Add(-clockSkew)) {
		return fmt.Errorf("%w: presigned URL is dated %s, in the future", ErrUnauthenticated, signedAt.UTC())
	}
	return nil
}

// isSTSHost reports whether host is sts.amazonaws.com or a regional
// sts.<region>.amazonaws.com in any partition.
//
// A substring search would pass "sts.amazonaws.com.attacker.example", which
// contains the global host, so this matches on suffix and label shape.
func isSTSHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch host {
	case "sts.amazonaws.com", "sts.amazonaws.com.cn":
		return true
	}
	if !strings.HasPrefix(host, "sts.") {
		return false
	}
	rest, ok := strings.CutSuffix(host, ".amazonaws.com")
	if !ok {
		if rest, ok = strings.CutSuffix(host, ".amazonaws.com.cn"); !ok {
			return false
		}
	}
	// rest is now "sts.<region>"; the region must be a single non-empty label.
	region, ok := strings.CutPrefix(rest, "sts.")
	return ok && region != "" && !strings.Contains(region, ".")
}

// callSTS replays the presigned request and decodes the identity AWS reports.
//
// The request is a POST with no body: the signature covers the query string,
// so the presigned URL is valid for either verb, and POST keeps the credential
// out of intermediary access logs that record only the method and path.
func callSTS(r *http.Request, client *http.Client, u *url.URL, endpoint string) (*callerIdentity, error) {
	target := u.String()
	if endpoint != "" {
		// Redirect the hop while preserving the signed query string. The URL
		// the caller presented already passed the allowlist.
		redirected := *u
		ep, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("inbound awssts: invalid endpoint override %q: %w", endpoint, err)
		}
		redirected.Scheme, redirected.Host = ep.Scheme, ep.Host
		redirected.Path = strings.TrimSuffix(ep.Path, "/") + u.Path
		target = redirected.String()
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, nil)
	if err != nil {
		return nil, fmt.Errorf("inbound awssts: building STS request: %w", err)
	}
	req.Header.Set("Accept", "application/xml")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("inbound awssts: calling STS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("inbound awssts: reading STS response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// STS answers 403 for a bad signature and 400 for an expired one;
		// both point at the caller's credential rather than an AWS outage.
		if resp.StatusCode >= 500 {
			return nil, fmt.Errorf("inbound awssts: STS returned %s (upstream failure)", resp.Status)
		}
		return nil, fmt.Errorf("%w: STS rejected the presigned request (%s)", ErrUnauthenticated, resp.Status)
	}

	var out callerIdentity
	if err := xml.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("inbound awssts: decoding STS response: %w", err)
	}
	if out.Arn == "" {
		return nil, fmt.Errorf("inbound awssts: STS response carried no ARN")
	}
	return &out, nil
}

// parseARN splits an ARN into the pieces subject templates can reference.
// arn:<partition>:<service>:<region>:<account>:<resource>
func parseARN(arn string) (arnParts, error) {
	f := strings.SplitN(arn, ":", 6)
	if len(f) != 6 || f[0] != "arn" {
		return arnParts{}, fmt.Errorf("inbound awssts: malformed ARN %q", arn)
	}
	p := arnParts{
		full:      arn,
		partition: f[1],
		service:   f[2],
		account:   f[4],
	}
	// Resource shapes seen here: "assumed-role/<role>/<session>" for STS,
	// "user/<name>" for a long-lived IAM user, "root" for the account root.
	res := strings.Split(f[5], "/")
	switch {
	case len(res) >= 3 && res[0] == "assumed-role":
		p.role = res[1]
		p.session = strings.Join(res[2:], "/")
	case len(res) == 2:
		p.role = res[1]
	default:
		p.role = f[5]
	}
	return p, nil
}

// compileRoleMappings validates and orders the configured patterns.
//
// Go map iteration is randomized, so evaluating mappings in map order would
// make the resolved subject nondeterministic whenever two patterns overlap.
// Sorting by specificity (fewest wildcards, then longest pattern) lets
// "arn:aws:sts::1234:assumed-role/Admin/*" win over "arn:aws:sts::*", the
// reading an operator expects from an overlapping allowlist.
func compileRoleMappings(m map[string]string) ([]roleMapping, error) {
	out := make([]roleMapping, 0, len(m))
	for pattern, template := range m {
		if pattern == "" {
			return nil, fmt.Errorf("inbound awssts: role mapping has an empty ARN pattern")
		}
		if template == "" {
			return nil, fmt.Errorf("inbound awssts: role mapping %q has an empty subject template", pattern)
		}
		out = append(out, roleMapping{pattern: pattern, template: template})
	}
	sort.Slice(out, func(i, j int) bool {
		wi, wj := strings.Count(out[i].pattern, "*"), strings.Count(out[j].pattern, "*")
		if wi != wj {
			return wi < wj
		}
		if len(out[i].pattern) != len(out[j].pattern) {
			return len(out[i].pattern) > len(out[j].pattern)
		}
		return out[i].pattern < out[j].pattern
	})
	return out, nil
}

// applyMappings returns the subject produced by the first matching mapping.
func applyMappings(mappings []roleMapping, p arnParts) (subject, pattern string, ok bool) {
	for _, m := range mappings {
		if !globMatch(m.pattern, p.full) {
			continue
		}
		return expandTemplate(m.template, p), m.pattern, true
	}
	return "", "", false
}

// expandTemplate substitutes {placeholder} references in a subject template.
// Unknown placeholders stay verbatim so a typo surfaces in audit logs
// instead of collapsing two principals onto one subject.
func expandTemplate(tmpl string, p arnParts) string {
	if !strings.ContainsRune(tmpl, '{') {
		return tmpl
	}
	r := strings.NewReplacer(
		"{arn}", p.full,
		"{account}", p.account,
		"{role}", p.role,
		"{session}", p.session,
		"{partition}", p.partition,
		"{service}", p.service,
	)
	return r.Replace(tmpl)
}
