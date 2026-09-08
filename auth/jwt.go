// Package auth provides transport-neutral RS256 JWT signing and verification.
package auth

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const minimumRSAKeyBits = 2048

var (
	ErrSigningKeyUnavailable      = errors.New("JWT signing key is unavailable")
	ErrVerificationKeyUnavailable = errors.New("JWT verification key is unavailable")
	ErrUnexpectedAlgorithm        = errors.New("JWT must use RS256")
)

// Clock makes time-sensitive token behavior deterministic in tests.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Option configures a Manager.
type Option func(*options)

type options struct {
	clock Clock
}

// WithClock replaces the wall clock. It is primarily useful for tests.
func WithClock(clock Clock) Option {
	return func(options *options) {
		if clock != nil {
			options.clock = clock
		}
	}
}

// Subject is the Ardyn identity carried in a JWT.
type Subject struct {
	UserID string   `json:"user_id"`
	Roles  []string `json:"roles"`
}

// Claims is the typed JWT payload. RegisteredClaims is deliberately embedded
// so issuer, audience and time constraints are always represented explicitly.
type Claims struct {
	Subject
	jwt.RegisteredClaims
}

// Signer and Verifier allow applications to depend on the capability they use.
type Signer interface {
	Sign(Subject, time.Duration) (string, error)
}

type Verifier interface {
	Verify(string) (Claims, error)
}

// Manager holds parsed RSA keys once. It never exposes private-key material.
// A manager can sign, verify, or do both depending on the configured keys.
type Manager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
	clock      Clock
}

// New creates a JWT manager. Issuer and audience are mandatory so all tokens
// produced and accepted by this manager have bounded service context.
func New(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, issuer, audience string, opts ...Option) (*Manager, error) {
	if issuer == "" {
		return nil, errors.New("JWT issuer is required")
	}
	if audience == "" {
		return nil, errors.New("JWT audience is required")
	}
	if privateKey == nil && publicKey == nil {
		return nil, errors.New("at least one JWT key is required")
	}
	if err := validatePrivateKey(privateKey); err != nil {
		return nil, err
	}
	if err := validatePublicKey(publicKey); err != nil {
		return nil, err
	}
	if privateKey != nil && publicKey != nil && (privateKey.PublicKey.N.Cmp(publicKey.N) != 0 || privateKey.PublicKey.E != publicKey.E) {
		return nil, errors.New("JWT private and public keys do not match")
	}

	configuration := options{clock: systemClock{}}
	for _, option := range opts {
		if option != nil {
			option(&configuration)
		}
	}
	return &Manager{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     issuer,
		audience:   audience,
		clock:      configuration.clock,
	}, nil
}

// LoadRSAPrivateKeyFile reads and parses a PKCS#1 or PKCS#8 RSA private key.
func LoadRSAPrivateKeyFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read RSA private key %q: %w", path, err)
	}
	return ParseRSAPrivateKeyPEM(data)
}

// LoadRSAPublicKeyFile reads and parses a PKIX or PKCS#1 RSA public key.
func LoadRSAPublicKeyFile(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read RSA public key %q: %w", path, err)
	}
	return ParseRSAPublicKeyPEM(data)
}

// ParseRSAPrivateKeyPEM parses private-key material at startup. The parsed key,
// not its PEM bytes, is retained by Manager.
func ParseRSAPrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, err := singlePEMBlock(data)
	if err != nil {
		return nil, fmt.Errorf("parse RSA private key: %w", err)
	}

	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("PEM does not contain an RSA private key")
			}
		}
	default:
		return nil, fmt.Errorf("unsupported private-key PEM type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if err := validatePrivateKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

// ParseRSAPublicKeyPEM parses a public key without accepting unrelated PEM
// blocks or silently ignoring trailing data.
func ParseRSAPublicKeyPEM(data []byte) (*rsa.PublicKey, error) {
	block, err := singlePEMBlock(data)
	if err != nil {
		return nil, fmt.Errorf("parse RSA public key: %w", err)
	}

	var key *rsa.PublicKey
	switch block.Type {
	case "RSA PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	case "PUBLIC KEY":
		var parsed any
		parsed, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("PEM does not contain an RSA public key")
			}
		}
	default:
		return nil, fmt.Errorf("unsupported public-key PEM type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if err := validatePublicKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

func singlePEMBlock(data []byte) (*pem.Block, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("multiple or trailing PEM blocks are not allowed")
	}
	return block, nil
}

func validatePrivateKey(key *rsa.PrivateKey) error {
	if key == nil {
		return nil
	}
	if err := key.Validate(); err != nil {
		return fmt.Errorf("invalid RSA private key: %w", err)
	}
	return validatePublicKey(&key.PublicKey)
}

func validatePublicKey(key *rsa.PublicKey) error {
	if key == nil {
		return nil
	}
	if key.N == nil || key.E < 2 {
		return errors.New("invalid RSA public key")
	}
	if key.N.BitLen() < minimumRSAKeyBits {
		return fmt.Errorf("RSA key must be at least %d bits", minimumRSAKeyBits)
	}
	return nil
}

// Sign creates an RS256 JWT with issued-at, not-before and expiry claims.
func (manager *Manager) Sign(subject Subject, ttl time.Duration) (string, error) {
	if manager.privateKey == nil {
		return "", ErrSigningKeyUnavailable
	}
	if subject.UserID == "" {
		return "", errors.New("JWT subject user ID is required")
	}
	if ttl <= 0 {
		return "", errors.New("JWT TTL must be positive")
	}

	now := manager.clock.Now().UTC()
	claims := Claims{
		Subject: Subject{UserID: subject.UserID, Roles: append([]string(nil), subject.Roles...)},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    manager.issuer,
			Audience:  jwt.ClaimStrings{manager.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(manager.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signed, nil
}

// Verify accepts only RS256 tokens and validates signature, issuer, audience,
// expiry, not-before and issued-at claims.
func (manager *Manager) Verify(rawToken string) (Claims, error) {
	if manager.publicKey == nil {
		return Claims{}, ErrVerificationKeyUnavailable
	}
	if rawToken == "" {
		return Claims{}, errors.New("JWT is empty")
	}

	claims := Claims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(manager.issuer),
		jwt.WithAudience(manager.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithTimeFunc(manager.clock.Now),
	)
	_, err := parser.ParseWithClaims(rawToken, &claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, ErrUnexpectedAlgorithm
		}
		return manager.publicKey, nil
	})
	if err != nil {
		return Claims{}, fmt.Errorf("verify JWT: %w", err)
	}
	if claims.UserID == "" {
		return Claims{}, errors.New("verify JWT: user ID claim is required")
	}
	return claims, nil
}
