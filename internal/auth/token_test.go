package auth

import (
	"testing"

	"intelligence-platform/pkg/middleware"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateTokenPair(t *testing.T) {
	s := &Service{jwtSecret: "access-key", jwtRefreshSecret: "refresh-key"}
	u := &User{ID: "u1", Email: "a@b.c", Role: "admin", ClearanceLevel: 5}

	tp, err := s.generateTokenPair(u)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	if tp.AccessToken == "" || tp.RefreshToken == "" {
		t.Fatal("tokens must be non-empty")
	}

	claims := &middleware.Claims{}
	tok, err := jwt.ParseWithClaims(tp.AccessToken, claims, func(*jwt.Token) (interface{}, error) {
		return []byte("access-key"), nil
	})
	if err != nil || !tok.Valid {
		t.Fatalf("access token should be valid: %v", err)
	}
	if claims.UserID != "u1" || claims.Role != "admin" || claims.ClearanceLevel != 5 {
		t.Fatalf("claims mismatch: %+v", claims)
	}

	// Access token must not validate against the refresh key.
	bad, err := jwt.ParseWithClaims(tp.AccessToken, &middleware.Claims{}, func(*jwt.Token) (interface{}, error) {
		return []byte("refresh-key"), nil
	})
	if err == nil && bad.Valid {
		t.Fatal("access token must not validate with the refresh secret")
	}
}
