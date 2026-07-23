package inbound

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// amzTime formats a timestamp the way SigV4 does.
func amzTime(t time.Time) string { return t.UTC().Format("20060102T150405Z") }

// presign builds a URL shaped like a real SigV4-presigned
// sts:GetCallerIdentity call. The signature is not verifiable locally — the
// gateway never checks it, AWS does — so any non-empty value serves. The
// timestamp is stamped at call time so the URL is fresh against the default
// clock; tests that care about staleness override X-Amz-Date and Now.
func presign(host string, override map[string]string) string {
	q := url.Values{
		"Action":               {"GetCallerIdentity"},
		"Version":              {"2011-06-15"},
		"X-Amz-Algorithm":      {"AWS4-HMAC-SHA256"},
		"X-Amz-Credential":     {"AKIAEXAMPLE/20260727/us-east-1/sts/aws4_request"},
		"X-Amz-Date":           {amzTime(time.Now())},
		"X-Amz-Expires":        {"60"},
		"X-Amz-SignedHeaders":  {"host"},
		"X-Amz-Signature":      {"deadbeef"},
		"X-Amz-Security-Token": {"session-token"},
	}
	for k, v := range override {
		if v == "" {
			q.Del(k)
			continue
		}
		q.Set(k, v)
	}
	return "https://" + host + "/?" + q.Encode()
}

// stsRequest carries a presigned URL in the header the resolver reads.
func stsRequest(presigned string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if presigned != "" {
		r.Header.Set(PresignedHeader, presigned)
	}
	return r
}

// fakeSTS answers GetCallerIdentity with a configurable ARN.
type fakeSTS struct {
	srv    *httptest.Server
	arn    atomic.Value
	status atomic.Int64
	calls  atomic.Int64
	// lastQuery records the query string the resolver forwarded, proving the
	// caller's signature survives the endpoint override.
	lastQuery  atomic.Value
	lastMethod atomic.Value
}

func newFakeSTS(t *testing.T, arn string) *fakeSTS {
	t.Helper()
	s := &fakeSTS{}
	s.arn.Store(arn)
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		s.lastQuery.Store(r.URL.RawQuery)
		s.lastMethod.Store(r.Method)
		if code := s.status.Load(); code != 0 {
			http.Error(w, "<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>", int(code))
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>%s</Arn>
    <UserId>AROAEXAMPLE:session</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>`, s.arn.Load())
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func TestAWSSTSMapsARNToSubject(t *testing.T) {
	cases := []struct {
		name     string
		arn      string
		mappings map[string]string
		want     string
	}{
		{
			name:     "literal subject",
			arn:      "arn:aws:sts::123456789012:assumed-role/DeployRole/i-0abc",
			mappings: map[string]string{"arn:aws:sts::123456789012:assumed-role/DeployRole/*": "deployer"},
			want:     "deployer",
		},
		{
			name:     "template interpolates role and session",
			arn:      "arn:aws:sts::123456789012:assumed-role/DeployRole/alice",
			mappings: map[string]string{"arn:aws:sts::*:assumed-role/*": "{role}/{session}"},
			want:     "DeployRole/alice",
		},
		{
			name:     "template interpolates account",
			arn:      "arn:aws:sts::123456789012:assumed-role/Ops/bob",
			mappings: map[string]string{"arn:aws:sts::*": "aws:{account}:{role}"},
			want:     "aws:123456789012:Ops",
		},
		{
			name:     "iam user arn",
			arn:      "arn:aws:iam::123456789012:user/carol",
			mappings: map[string]string{"arn:aws:iam::*:user/*": "user-{role}"},
			want:     "user-carol",
		},
		{
			name: "most specific pattern wins regardless of map order",
			arn:  "arn:aws:sts::123456789012:assumed-role/Admin/root",
			mappings: map[string]string{
				"arn:aws:sts::*": "generic",
				"arn:aws:sts::123456789012:assumed-role/Admin/*": "admin",
				"arn:*": "very-generic",
			},
			want: "admin",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newFakeSTS(t, tc.arn)
			res, err := AWSSTS(AWSSTSOptions{
				RoleMappings: tc.mappings,
				Endpoint:     s.srv.URL,
				HTTPClient:   s.srv.Client(),
			})
			if err != nil {
				t.Fatalf("AWSSTS: %v", err)
			}
			id, err := res(stsRequest(presign("sts.amazonaws.com", nil)))
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if id.Subject != tc.want {
				t.Errorf("subject = %q, want %q", id.Subject, tc.want)
			}
			if id.Claims["arn"] != tc.arn {
				t.Errorf("arn claim = %v, want %q", id.Claims["arn"], tc.arn)
			}
		})
	}
}

func TestAWSSTSMappingOrderIsDeterministic(t *testing.T) {
	// Go randomizes map iteration; resolving the same ARN must still yield the
	// same subject on every construction, or identity would flap per process.
	arn := "arn:aws:sts::123456789012:assumed-role/Admin/root"
	mappings := map[string]string{
		"arn:aws:sts::*": "generic",
		"arn:aws:sts::123456789012:assumed-role/Admin/*": "admin",
		"arn:aws:sts::123456789012:*":                    "account-wide",
	}
	s := newFakeSTS(t, arn)
	for range 20 {
		res, err := AWSSTS(AWSSTSOptions{
			RoleMappings: mappings,
			Endpoint:     s.srv.URL,
			HTTPClient:   s.srv.Client(),
		})
		if err != nil {
			t.Fatalf("AWSSTS: %v", err)
		}
		id, err := res(stsRequest(presign("sts.amazonaws.com", nil)))
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if id.Subject != "admin" {
			t.Fatalf("subject = %q, want admin", id.Subject)
		}
	}
}

func TestAWSSTSRejectsUnmappedPrincipal(t *testing.T) {
	// An AWS identity with no mapping is an unknown principal; admitting it
	// under some default subject would silently grant access to any AWS
	// account in the world.
	s := newFakeSTS(t, "arn:aws:sts::999999999999:assumed-role/Stranger/x")
	res, err := AWSSTS(AWSSTSOptions{
		RoleMappings: map[string]string{"arn:aws:sts::123456789012:assumed-role/Deploy/*": "deployer"},
		Endpoint:     s.srv.URL,
		HTTPClient:   s.srv.Client(),
	})
	if err != nil {
		t.Fatalf("AWSSTS: %v", err)
	}
	_, err = res(stsRequest(presign("sts.amazonaws.com", nil)))
	if err == nil {
		t.Fatal("want rejection for an unmapped ARN")
	}
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("error %v does not wrap ErrUnauthenticated", err)
	}
}

func TestAWSSTSRejectsBadPresignedURLs(t *testing.T) {
	s := newFakeSTS(t, "arn:aws:sts::123456789012:assumed-role/Deploy/x")
	res, err := AWSSTS(AWSSTSOptions{
		RoleMappings: map[string]string{"arn:*": "anyone"},
		Endpoint:     s.srv.URL,
		HTTPClient:   s.srv.Client(),
	})
	if err != nil {
		t.Fatalf("AWSSTS: %v", err)
	}

	cases := []struct {
		name string
		url  string
	}{
		{"missing header", ""},
		{"plain http", "http://sts.amazonaws.com/?Action=GetCallerIdentity&X-Amz-Signature=a&X-Amz-Credential=b"},
		{"non-sts host", presign("evil.example.com", nil)},
		{"sts host as a prefix of an attacker domain", presign("sts.amazonaws.com.evil.example", nil)},
		{"sts substring in the middle", presign("evil-sts.amazonaws.com.attacker.net", nil)},
		{"multi-label fake region", presign("sts.us-east-1.evil.amazonaws.com", nil)},
		{"wrong action", presign("sts.amazonaws.com", map[string]string{"Action": "AssumeRole"})},
		{"unsigned", presign("sts.amazonaws.com", map[string]string{"X-Amz-Signature": ""})},
		{"no credential scope", presign("sts.amazonaws.com", map[string]string{"X-Amz-Credential": ""})},
		{"expiry beyond the cap", presign("sts.amazonaws.com", map[string]string{"X-Amz-Expires": "604800"})},
		{"non-numeric expiry", presign("sts.amazonaws.com", map[string]string{"X-Amz-Expires": "soon"})},
		{"zero expiry", presign("sts.amazonaws.com", map[string]string{"X-Amz-Expires": "0"})},
		{"unparseable url", "https://sts.amazonaws.com/%zz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := s.calls.Load()
			_, err := res(stsRequest(tc.url))
			if err == nil {
				t.Fatal("want rejection")
			}
			if !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("error %v does not wrap ErrUnauthenticated", err)
			}
			// Validation must happen before the network hop: otherwise the
			// gateway is an SSRF proxy for any URL a caller supplies.
			if got := s.calls.Load(); got != before {
				t.Errorf("resolver dispatched %d request(s) for a URL it should have rejected", got-before)
			}
		})
	}
}

func TestAWSSTSAcceptsRegionalHosts(t *testing.T) {
	s := newFakeSTS(t, "arn:aws:sts::123456789012:assumed-role/Deploy/x")
	res, err := AWSSTS(AWSSTSOptions{
		RoleMappings: map[string]string{"arn:*": "anyone"},
		Endpoint:     s.srv.URL,
		HTTPClient:   s.srv.Client(),
	})
	if err != nil {
		t.Fatalf("AWSSTS: %v", err)
	}
	for _, host := range []string{
		"sts.amazonaws.com",
		"sts.us-east-1.amazonaws.com",
		"sts.eu-central-1.amazonaws.com",
		"sts.us-gov-west-1.amazonaws.com",
		"sts.cn-north-1.amazonaws.com.cn",
		"STS.US-EAST-1.AMAZONAWS.COM",
	} {
		if _, err := res(stsRequest(presign(host, nil))); err != nil {
			t.Errorf("host %q rejected: %v", host, err)
		}
	}
}

func TestAWSSTSForwardsSignedQueryToEndpoint(t *testing.T) {
	// The endpoint override must redirect only the network hop: dropping or
	// rewriting the signed query would invalidate the caller's signature
	// against real AWS.
	s := newFakeSTS(t, "arn:aws:sts::123456789012:assumed-role/Deploy/x")
	res, err := AWSSTS(AWSSTSOptions{
		RoleMappings: map[string]string{"arn:*": "anyone"},
		Endpoint:     s.srv.URL,
		HTTPClient:   s.srv.Client(),
	})
	if err != nil {
		t.Fatalf("AWSSTS: %v", err)
	}
	if _, err := res(stsRequest(presign("sts.amazonaws.com", nil))); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	got, _ := url.ParseQuery(s.lastQuery.Load().(string))
	for _, k := range []string{"Action", "X-Amz-Signature", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Security-Token"} {
		if got.Get(k) == "" {
			t.Errorf("query parameter %q was not forwarded", k)
		}
	}
	if m := s.lastMethod.Load(); m != http.MethodPost {
		t.Errorf("method = %v, want POST", m)
	}
}

func TestAWSSTSUpstreamFailures(t *testing.T) {
	cases := []struct {
		name         string
		status       int
		wantAuthFail bool
	}{
		{"signature rejected", http.StatusForbidden, true},
		{"expired credential", http.StatusBadRequest, true},
		{"sts outage", http.StatusInternalServerError, false},
		{"sts unavailable", http.StatusServiceUnavailable, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newFakeSTS(t, "arn:aws:sts::123456789012:assumed-role/Deploy/x")
			s.status.Store(int64(tc.status))
			res, err := AWSSTS(AWSSTSOptions{
				RoleMappings: map[string]string{"arn:*": "anyone"},
				Endpoint:     s.srv.URL,
				HTTPClient:   s.srv.Client(),
			})
			if err != nil {
				t.Fatalf("AWSSTS: %v", err)
			}
			_, err = res(stsRequest(presign("sts.amazonaws.com", nil)))
			if err == nil {
				t.Fatal("want failure")
			}
			// A 5xx means AWS is broken, not that the caller is unauthorized;
			// conflating them would hide outages behind 401s.
			if got := errors.Is(err, ErrUnauthenticated); got != tc.wantAuthFail {
				t.Errorf("errors.Is(err, ErrUnauthenticated) = %v, want %v (err: %v)", got, tc.wantAuthFail, err)
			}
		})
	}
}

func TestAWSSTSRejectsMalformedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult></GetCallerIdentityResult></GetCallerIdentityResponse>`))
	}))
	defer srv.Close()

	res, err := AWSSTS(AWSSTSOptions{
		RoleMappings: map[string]string{"arn:*": "anyone"},
		Endpoint:     srv.URL,
		HTTPClient:   srv.Client(),
	})
	if err != nil {
		t.Fatalf("AWSSTS: %v", err)
	}
	if _, err := res(stsRequest(presign("sts.amazonaws.com", nil))); err == nil {
		t.Fatal("want failure when STS returns no ARN")
	}
}

func TestAWSSTSConfigValidation(t *testing.T) {
	cases := []struct {
		name     string
		mappings map[string]string
	}{
		{"no mappings", nil},
		{"empty mappings", map[string]string{}},
		{"empty pattern", map[string]string{"": "someone"}},
		{"empty subject template", map[string]string{"arn:*": ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := AWSSTS(AWSSTSOptions{RoleMappings: tc.mappings}); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestParseARN(t *testing.T) {
	cases := []struct {
		arn                          string
		role, session, account, part string
		wantErr                      bool
	}{
		{
			arn:  "arn:aws:sts::123456789012:assumed-role/Deploy/i-0abc",
			role: "Deploy", session: "i-0abc", account: "123456789012", part: "aws",
		},
		{
			arn:  "arn:aws-us-gov:sts::123456789012:assumed-role/Gov/sess",
			role: "Gov", session: "sess", account: "123456789012", part: "aws-us-gov",
		},
		{
			// A session name may itself contain slashes; everything after the
			// role belongs to the session.
			arn:  "arn:aws:sts::123456789012:assumed-role/Deploy/a/b/c",
			role: "Deploy", session: "a/b/c", account: "123456789012", part: "aws",
		},
		{
			arn:  "arn:aws:iam::123456789012:user/carol",
			role: "carol", account: "123456789012", part: "aws",
		},
		{
			arn:  "arn:aws:iam::123456789012:root",
			role: "root", account: "123456789012", part: "aws",
		},
		{arn: "not-an-arn", wantErr: true},
		{arn: "arn:aws:sts", wantErr: true},
		{arn: "xyz:aws:sts::123456789012:assumed-role/A/B", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.arn, func(t *testing.T) {
			p, err := parseARN(tc.arn)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", p)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseARN: %v", err)
			}
			if p.role != tc.role || p.session != tc.session || p.account != tc.account || p.partition != tc.part {
				t.Errorf("got role=%q session=%q account=%q partition=%q; want %q/%q/%q/%q",
					p.role, p.session, p.account, p.partition, tc.role, tc.session, tc.account, tc.part)
			}
		})
	}
}

func TestExpandTemplateLeavesUnknownPlaceholders(t *testing.T) {
	// A typo must be visible in the resolved subject rather than silently
	// collapsing distinct principals onto one identity.
	p := arnParts{full: "arn:aws:sts::1:assumed-role/R/S", role: "R", session: "S", account: "1"}
	if got := expandTemplate("{role}-{nope}", p); got != "R-{nope}" {
		t.Errorf("got %q, want %q", got, "R-{nope}")
	}
	if got := expandTemplate("literal", p); got != "literal" {
		t.Errorf("got %q, want literal", got)
	}
}

func TestAWSSTSExpiryCapIsFifteenMinutes(t *testing.T) {
	// Guards the constant itself: a presigned URL is a bearer credential, so
	// widening this silently would extend every leak's blast radius.
	if maxPresignedExpiry != 15*time.Minute {
		t.Fatalf("maxPresignedExpiry = %v, want 15m", maxPresignedExpiry)
	}
	s := newFakeSTS(t, "arn:aws:sts::123456789012:assumed-role/Deploy/x")
	res, err := AWSSTS(AWSSTSOptions{
		RoleMappings: map[string]string{"arn:*": "anyone"},
		Endpoint:     s.srv.URL,
		HTTPClient:   s.srv.Client(),
	})
	if err != nil {
		t.Fatalf("AWSSTS: %v", err)
	}
	if _, err := res(stsRequest(presign("sts.amazonaws.com", map[string]string{"X-Amz-Expires": "900"}))); err != nil {
		t.Errorf("900s expiry rejected: %v", err)
	}
	if _, err := res(stsRequest(presign("sts.amazonaws.com", map[string]string{"X-Amz-Expires": "901"}))); err == nil {
		t.Error("901s expiry accepted, want rejection")
	}
}

func TestAWSSTSFreshness(t *testing.T) {
	// A presigned URL is a bearer credential. Rejecting a stale one locally
	// costs no round trip and closes the window a leaked URL stays usable,
	// even if AWS would still honour it.
	signedAt := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		now  time.Time
		ok   bool
	}{
		{"within the lifetime", signedAt.Add(30 * time.Second), true},
		{"just past the lifetime, inside skew", signedAt.Add(90 * time.Second), true},
		{"well past the lifetime", signedAt.Add(30 * time.Minute), false},
		{"slightly early, inside skew", signedAt.Add(-time.Minute), true},
		{"far in the future relative to the signature", signedAt.Add(-time.Hour), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newFakeSTS(t, "arn:aws:sts::123456789012:assumed-role/Deploy/x")
			res, err := AWSSTS(AWSSTSOptions{
				RoleMappings: map[string]string{"arn:*": "anyone"},
				Endpoint:     s.srv.URL,
				HTTPClient:   s.srv.Client(),
				Now:          func() time.Time { return tc.now },
			})
			if err != nil {
				t.Fatalf("AWSSTS: %v", err)
			}
			u := presign("sts.amazonaws.com", map[string]string{
				"X-Amz-Date":    amzTime(signedAt),
				"X-Amz-Expires": "60",
			})
			_, err = res(stsRequest(u))
			if tc.ok {
				if err != nil {
					t.Fatalf("want acceptance, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("want rejection")
			}
			if !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("error %v does not wrap ErrUnauthenticated", err)
			}
			// Staleness is decided locally, before any network hop.
			if n := s.calls.Load(); n != 0 {
				t.Errorf("STS called %d times for a stale URL, want 0", n)
			}
		})
	}
}

func TestAWSSTSMalformedDateIsRejected(t *testing.T) {
	s := newFakeSTS(t, "arn:aws:sts::123456789012:assumed-role/Deploy/x")
	res, err := AWSSTS(AWSSTSOptions{
		RoleMappings: map[string]string{"arn:*": "anyone"},
		Endpoint:     s.srv.URL,
		HTTPClient:   s.srv.Client(),
	})
	if err != nil {
		t.Fatalf("AWSSTS: %v", err)
	}
	u := presign("sts.amazonaws.com", map[string]string{"X-Amz-Date": "yesterday"})
	if _, err := res(stsRequest(u)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("error %v does not wrap ErrUnauthenticated", err)
	}
}

func TestAWSSTSWithoutExpiresSkipsFreshnessCheck(t *testing.T) {
	// SigV4 permits the lifetime to be implied rather than stated; AWS remains
	// the authority on whether such a signature is still valid.
	s := newFakeSTS(t, "arn:aws:sts::123456789012:assumed-role/Deploy/x")
	res, err := AWSSTS(AWSSTSOptions{
		RoleMappings: map[string]string{"arn:*": "anyone"},
		Endpoint:     s.srv.URL,
		HTTPClient:   s.srv.Client(),
		Now:          func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("AWSSTS: %v", err)
	}
	u := presign("sts.amazonaws.com", map[string]string{"X-Amz-Expires": ""})
	if _, err := res(stsRequest(u)); err != nil {
		t.Fatalf("resolve: %v", err)
	}
}
