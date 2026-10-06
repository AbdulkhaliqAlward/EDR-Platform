package uninstalltoken

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

const agentA = "65a9e961-9cfa-447b-be63-4ce26cb563fc"
const agentB = "11111111-2222-3333-4444-555555555555"

// mintLikeServer reproduces security.SignUninstallToken byte-for-byte so this
// test proves the agent verifier accepts exactly what the server mints. If the
// server format changes, this must change in lockstep.
func mintLikeServer(t *testing.T, priv ed25519.PrivateKey, c Claims) string {
	t.Helper()
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func keypair(t *testing.T) (pubB64 string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub), priv
}

func validClaims(now time.Time) Claims {
	return Claims{
		V:         Version,
		AgentID:   agentA,
		Action:    Action,
		Nonce:     "Zm9vYmFyMTIzNDU2Nzg5",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(30 * time.Minute).Unix(),
	}
}

func TestVerify_HappyPath(t *testing.T) {
	pubB64, priv := keypair(t)
	now := time.Now()
	tok := mintLikeServer(t, priv, validClaims(now))

	claims, err := Verify(pubB64, tok, agentA, now)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if claims.AgentID != agentA {
		t.Fatalf("agent id = %q", claims.AgentID)
	}
}

func TestVerify_Failures(t *testing.T) {
	pubB64, priv := keypair(t)
	now := time.Now()

	// A token signed by a DIFFERENT key must be rejected.
	_, otherPriv := keypair(t)

	cases := []struct {
		name    string
		token   func() string
		agentID string
		now     time.Time
		want    error
	}{
		{"wrong agent", func() string { return mintLikeServer(t, priv, validClaims(now)) }, agentB, now, ErrWrongAgent},
		{"expired", func() string {
			c := validClaims(now.Add(-1 * time.Hour))
			return mintLikeServer(t, priv, c)
		}, agentA, now, ErrExpired},
		{"not yet valid", func() string {
			c := validClaims(now.Add(1 * time.Hour))
			return mintLikeServer(t, priv, c)
		}, agentA, now, ErrNotYetValid},
		{"wrong action", func() string {
			c := validClaims(now)
			c.Action = "reboot"
			return mintLikeServer(t, priv, c)
		}, agentA, now, ErrWrongAction},
		{"wrong version", func() string {
			c := validClaims(now)
			c.V = 99
			return mintLikeServer(t, priv, c)
		}, agentA, now, ErrWrongVersion},
		{"forged signature (other key)", func() string {
			return mintLikeServer(t, otherPriv, validClaims(now))
		}, agentA, now, ErrBadSignature},
		{"tampered payload", func() string {
			tok := mintLikeServer(t, priv, validClaims(now))
			// Flip the agent id in the payload but keep the old signature.
			c := validClaims(now)
			c.AgentID = agentB
			payload, _ := json.Marshal(c)
			sigPart := tok[len(tok)-86:] // not exact; just ensure mismatch below
			_ = sigPart
			return base64.RawURLEncoding.EncodeToString(payload) + "." + tok[len(tok)-10:]
		}, agentB, now, ErrBadSignature},
		{"malformed - no dot", func() string { return "notatoken" }, agentA, now, ErrMalformed},
		{"malformed - bad base64", func() string { return "@@@.@@@" }, agentA, now, ErrMalformed},
		{"empty", func() string { return "" }, agentA, now, ErrEmptyToken},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(pubB64, tc.token(), tc.agentID, tc.now)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// TestVerify_ServerGoldenVector verifies a token minted by the SERVER's
// security.SignUninstallToken (connection-manager module), proving the two
// independently-declared wire formats are byte-compatible. The vector was
// produced from a deterministic Ed25519 seed; if either side's format drifts,
// this test fails. The token expires in ~100 years, so time is not a factor.
func TestVerify_ServerGoldenVector(t *testing.T) {
	const goldenPub = "ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ="
	const goldenToken = "eyJ2IjoxLCJhZ2VudF9pZCI6IjY1YTllOTYxLTljZmEtNDQ3Yi1iZTYzLTRjZTI2Y2I1NjNmYyIsImFjdGlvbiI6InVuaW5zdGFsbCIsIm5vbmNlIjoiY0RmUWtXU3d6RFlDTW1NUlRXTy04ZyIsImlzc3VlZF9hdCI6MTc5MTI5ODU3NCwiZXhwaXJlc19hdCI6NDk0NDg5ODU3NH0.VtPEknKk89a3-G0ed21v4hsk7T-q6zNGvG99bLB9tHhlXMk8Q2hq2cBeBqAIra6G4-CURNmvGCCkkGe55dZuCg"

	claims, err := Verify(goldenPub, goldenToken, agentA, time.Unix(1791298600, 0))
	if err != nil {
		t.Fatalf("server-minted token rejected: %v", err)
	}
	if claims.AgentID != agentA || claims.Action != Action || claims.V != Version {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// The same token must be rejected for a different agent.
	if _, err := Verify(goldenPub, goldenToken, agentB, time.Unix(1791298600, 0)); !errors.Is(err, ErrWrongAgent) {
		t.Fatalf("expected ErrWrongAgent for different agent, got %v", err)
	}
}

// TestVerify_PrefixedLocalID covers the real-world bug: the device stores its
// ID as "agent-<UUID>" (synced from the certificate CN), while the dashboard
// mints the token with the bare UUID. Both must be treated as the same agent.
func TestVerify_PrefixedLocalID(t *testing.T) {
	pubB64, priv := keypair(t)
	now := time.Now()
	tok := mintLikeServer(t, priv, validClaims(now))

	for _, local := range []string{
		"agent-" + agentA,
		"AGENT-" + agentA,
		strings.ToUpper(agentA),
		"  " + agentA + "  ",
	} {
		if _, err := Verify(pubB64, tok, local, now); err != nil {
			t.Errorf("local ID %q should match token agent %q, got %v", local, agentA, err)
		}
	}
	// A different (e.g. random fallback) ID must still be rejected.
	for _, local := range []string{"agent-" + agentB, agentB, "not-a-uuid", "agent-", ""} {
		if _, err := Verify(pubB64, tok, local, now); !errors.Is(err, ErrWrongAgent) {
			t.Errorf("local ID %q: got %v, want ErrWrongAgent", local, err)
		}
	}
}

func TestNormalizeAgentID(t *testing.T) {
	cases := map[string]string{
		agentA:                             agentA,
		"agent-" + agentA:                  agentA,
		"Agent-" + strings.ToUpper(agentA): agentA,
		"":                                 "",
		"agent-":                           "",
		"agent-xyz":                        "",
		"hostname-pc":                      "",
	}
	for in, want := range cases {
		if got := NormalizeAgentID(in); got != want {
			t.Errorf("NormalizeAgentID(%q) = %q, want %q", in, got, want)
		}
	}
}

// selfSignedPEM builds a certificate with the given CN and DNS SANs.
func selfSignedPEM(t *testing.T, cn string, dns []string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestAgentIDFromCertPEM(t *testing.T) {
	// Exactly what the server issues: CN and DNS SAN "agent-<UUID>".
	serverShaped := selfSignedPEM(t, "agent-"+agentA, []string{"agent-" + agentA})
	if got := AgentIDFromCertPEM(serverShaped); got != agentA {
		t.Fatalf("server-shaped cert: got %q, want %q", got, agentA)
	}
	// DNS SAN takes precedence over CN (same rule as the server).
	sanWins := selfSignedPEM(t, "agent-"+agentB, []string{"agent-" + agentA})
	if got := AgentIDFromCertPEM(sanWins); got != agentA {
		t.Fatalf("SAN precedence: got %q, want %q", got, agentA)
	}
	// CN-only fallback.
	cnOnly := selfSignedPEM(t, "agent-"+agentB, nil)
	if got := AgentIDFromCertPEM(cnOnly); got != agentB {
		t.Fatalf("CN fallback: got %q, want %q", got, agentB)
	}
	// Garbage in → empty, never a guess.
	if got := AgentIDFromCertPEM([]byte("not a pem")); got != "" {
		t.Fatalf("garbage: got %q, want empty", got)
	}
	if got := AgentIDFromCertPEM(selfSignedPEM(t, "win10-host", nil)); got != "" {
		t.Fatalf("non-UUID CN: got %q, want empty", got)
	}
}

func TestVerify_NoEmbeddedKey(t *testing.T) {
	_, err := Verify("", "a.b", agentA, time.Now())
	if !errors.Is(err, ErrNoPublicKey) {
		t.Fatalf("got %v, want ErrNoPublicKey", err)
	}
}

func TestParsePublicKey_BadSize(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	if _, err := ParsePublicKey(short); err == nil {
		t.Fatal("expected error for wrong-size key")
	}
}
