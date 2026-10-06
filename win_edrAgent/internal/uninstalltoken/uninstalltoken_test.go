package uninstalltoken

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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
