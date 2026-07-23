package authserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// jwk is the subset of RFC 7517 we emit: a P-256 signing key.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// jwkSet is the RFC 7517 JWK Set document served at /.well-known/jwks.json.
type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// loadOrCreateKey returns the ES256 signing key. An empty path yields an
// ephemeral in-memory key: fine for tests and single-process dev, fatal for a
// restartable deployment because every restart invalidates outstanding tokens.
// A non-empty path is read if it exists and otherwise generated and persisted
// with 0600 so a restart keeps signing with the same key.
func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if path == "" {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}

	pemBytes, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, perr := parseECKey(pemBytes)
		if perr != nil {
			return nil, fmt.Errorf("signing key %s: %w", path, perr)
		}
		return key, nil
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("read signing key %s: %w", path, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal signing key: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create signing key dir: %w", err)
		}
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	// 0600: the private key is the root of trust for every token we mint.
	if err := os.WriteFile(path, block, 0o600); err != nil {
		return nil, fmt.Errorf("write signing key %s: %w", path, err)
	}
	return key, nil
}

// parseECKey accepts both PEM encodings Go's own tooling produces for EC keys:
// SEC1 ("EC PRIVATE KEY") and PKCS#8 ("PRIVATE KEY").
func parseECKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is %T, want ECDSA", parsed)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block %q, want EC PRIVATE KEY or PRIVATE KEY", block.Type)
	}
}

// keyID derives a stable kid from the public key: the first 16 characters of
// the RFC 7638 JWK thumbprint (base64url of SHA-256 over the canonical JWK).
// Truncation keeps JWT headers small; 96 bits of a hash is far beyond what a
// single-key server needs to disambiguate, and kid is a lookup hint, not a
// security boundary.
func keyID(pub *ecdsa.PublicKey) (string, error) {
	x, y, err := coords(pub)
	if err != nil {
		return "", err
	}
	// RFC 7638 canonical form: required members only, lexicographic order.
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, x, y)
	sum := sha256.Sum256([]byte(canonical))
	full := base64.RawURLEncoding.EncodeToString(sum[:])
	return full[:16], nil
}

// publicJWKS renders the single-key JWK Set advertised to clients.
func publicJWKS(pub *ecdsa.PublicKey, kid string) (jwkSet, error) {
	x, y, err := coords(pub)
	if err != nil {
		return jwkSet{}, err
	}
	return jwkSet{Keys: []jwk{{
		Kty: "EC",
		Crv: "P-256",
		X:   x,
		Y:   y,
		Use: "sig",
		Alg: "ES256",
		Kid: kid,
	}}}, nil
}

// coords encodes the affine coordinates as fixed-width base64url, which RFC
// 7518 §6.2.1.2 requires: left-padding to the curve's 32-byte field size is
// what makes two encodings of the same key byte-identical (and thumbprints
// stable).
func coords(pub *ecdsa.PublicKey) (string, string, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return "", "", fmt.Errorf("signing key must be EC P-256")
	}
	const size = 32
	xb := pub.X.Bytes()
	yb := pub.Y.Bytes()
	if len(xb) > size || len(yb) > size {
		return "", "", fmt.Errorf("P-256 coordinate longer than %d bytes", size)
	}
	x := make([]byte, size)
	y := make([]byte, size)
	copy(x[size-len(xb):], xb)
	copy(y[size-len(yb):], yb)
	return base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y), nil
}

// marshalJWKS is a convenience for the HTTP handler.
func marshalJWKS(set jwkSet) ([]byte, error) {
	b, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("encode JWKS: %w", err)
	}
	return b, nil
}
