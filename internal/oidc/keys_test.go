package oidc

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateAndSign(t *testing.T) {
	ks := GenerateKeySet()
	if ks == nil || ks.Private == nil || ks.Public == nil {
		t.Fatalf("keys not generated")
	}
	claims := jwt.MapClaims{"sub": "alice@example.com"}
	tok, err := ks.SignIDToken(claims)
	if err != nil {
		t.Fatalf("SignIDToken failed: %v", err)
	}
	if tok == "" {
		t.Fatalf("empty token")
	}
}
