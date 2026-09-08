package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type fixedClock struct{ time time.Time }

func (clock fixedClock) Now() time.Time { return clock.time }

func testManager(t *testing.T) (*Manager, *rsa.PrivateKey, fixedClock) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clock := fixedClock{time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	manager, err := New(key, &key.PublicKey, "ardyn-citizen", "ardyn-api", WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	return manager, key, clock
}

func TestSignAndVerify(t *testing.T) {
	manager, _, _ := testManager(t)
	token, err := manager.Sign(Subject{UserID: "user-1", Roles: []string{"admin"}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := manager.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != "user-1" || len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Fatalf("Verify() claims = %#v", claims)
	}
}

func TestVerifyRejectsExpiredTamperedAndWrongAlgorithmTokens(t *testing.T) {
	manager, _, clock := testManager(t)
	expired, err := manager.Sign(Subject{UserID: "user-1"}, -time.Second)
	if err == nil || expired != "" {
		t.Fatal("Sign() accepted a non-positive TTL")
	}

	token, err := manager.Sign(Subject{UserID: "user-1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[1] == "" {
		t.Fatalf("unexpected signed JWT shape: %q", token)
	}
	replacement := byte('A')
	if parts[1][0] == replacement {
		replacement = 'B'
	}
	// Mutating the payload segment changes the signed input deterministically.
	tampered := parts[0] + "." + string(replacement) + parts[1][1:] + "." + parts[2]
	if _, err := manager.Verify(tampered); err == nil {
		t.Fatal("Verify() accepted a tampered token")
	}
	if _, err := manager.Verify("not.a.jwt"); err == nil {
		t.Fatal("Verify() accepted a malformed token")
	}

	badAlgorithm := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "user-1", "iss": "ardyn-citizen", "aud": "ardyn-api",
		"iat": clock.Now().Unix(), "nbf": clock.Now().Unix(), "exp": clock.Now().Add(time.Hour).Unix(),
	})
	unsafeToken, err := badAlgorithm.SignedString([]byte("not-an-rsa-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(unsafeToken); err == nil {
		t.Fatal("Verify() accepted a non-RS256 token")
	}
}

func TestVerifyValidatesIssuerAudienceAndExpiry(t *testing.T) {
	manager, key, clock := testManager(t)
	makeToken := func(issuer, audience string, expiry time.Time) string {
		t.Helper()
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, Claims{
			Subject:          Subject{UserID: "user-1"},
			RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Audience: jwt.ClaimStrings{audience}, IssuedAt: jwt.NewNumericDate(clock.Now()), NotBefore: jwt.NewNumericDate(clock.Now()), ExpiresAt: jwt.NewNumericDate(expiry)},
		})
		raw, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for name, raw := range map[string]string{
		"issuer":   makeToken("other", "ardyn-api", clock.Now().Add(time.Hour)),
		"audience": makeToken("ardyn-citizen", "other", clock.Now().Add(time.Hour)),
		"expired":  makeToken("ardyn-citizen", "ardyn-api", clock.Now().Add(-time.Second)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := manager.Verify(raw); err == nil {
				t.Fatalf("Verify() accepted %s token", name)
			}
		})
	}
}

func TestVerifyRejectsMissingRequiredIdentity(t *testing.T) {
	manager, key, clock := testManager(t)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    "ardyn-citizen",
		Audience:  jwt.ClaimStrings{"ardyn-api"},
		IssuedAt:  jwt.NewNumericDate(clock.Now()),
		NotBefore: jwt.NewNumericDate(clock.Now()),
		ExpiresAt: jwt.NewNumericDate(clock.Now().Add(time.Hour)),
	})
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(raw); err == nil {
		t.Fatal("Verify() accepted a token without user_id")
	}
}

func TestNewRejectsInsecureOrIncompleteConfiguration(t *testing.T) {
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(weakKey, &weakKey.PublicKey, "issuer", "audience"); err == nil {
		t.Fatal("New() accepted a weak RSA key")
	}
	strongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(strongKey, &strongKey.PublicKey, "", "audience"); err == nil {
		t.Fatal("New() accepted an empty issuer")
	}
	if _, err := New(strongKey, &strongKey.PublicKey, "issuer", ""); err == nil {
		t.Fatal("New() accepted an empty audience")
	}
}

func TestPEMParsingAndKeyCapabilities(t *testing.T) {
	_, key, _ := testManager(t)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(t, key)})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustMarshalPKIX(t, &key.PublicKey)})
	if _, err := ParseRSAPrivateKeyPEM(append(privatePEM, []byte("garbage")...)); err == nil {
		t.Fatal("ParseRSAPrivateKeyPEM accepted trailing data")
	}
	if _, err := ParseRSAPrivateKeyPEM(privatePEM); err != nil {
		t.Fatalf("ParseRSAPrivateKeyPEM() error = %v", err)
	}
	if _, err := ParseRSAPublicKeyPEM(publicPEM); err != nil {
		t.Fatalf("ParseRSAPublicKeyPEM() error = %v", err)
	}
	verificationOnly, err := New(nil, &key.PublicKey, "ardyn-citizen", "ardyn-api")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verificationOnly.Sign(Subject{UserID: "user-1"}, time.Hour); err != ErrSigningKeyUnavailable {
		t.Fatalf("Sign() error = %v, want ErrSigningKeyUnavailable", err)
	}
	signingOnly, err := New(key, nil, "ardyn-citizen", "ardyn-api")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signingOnly.Verify("anything"); err != ErrVerificationKeyUnavailable {
		t.Fatalf("Verify() error = %v, want ErrVerificationKeyUnavailable", err)
	}
}

func mustMarshalPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustMarshalPKIX(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	data, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
