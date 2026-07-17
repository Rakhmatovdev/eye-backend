package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// signTestToken builds a signed JWT identical in shape to what auth.Service
// issues, without pulling in the auth package (would be an import cycle).
func signTestToken(t *testing.T, secret string, claims Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("failed to sign test token: %v", err)
	}
	return s
}

// TestRequireRole covers the actual RBAC gate used for every admin-only
// ("🔒") route registered in cmd/api/main.go (userAdminMW := mw.RequireRole
// ("admin")). It reads the role via GetUserRole, which pulls it from the
// gin context key set by the Auth middleware (ContextKeyRole) — so we seed
// that key directly instead of going through a real JWT/DB flow.
func TestRequireRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("non-admin gets 403", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/admin-only", nil)
		c.Set(ContextKeyRole, "analyst")

		RequireRole("admin")(c)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
		if !c.IsAborted() {
			t.Fatal("context should be aborted for a non-admin role")
		}
	})

	t.Run("admin passes", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/admin-only", nil)
		c.Set(ContextKeyRole, "admin")

		RequireRole("admin")(c)

		if c.IsAborted() {
			t.Fatal("context should not be aborted for the admin role")
		}
		if w.Code != http.StatusOK {
			t.Fatalf("expected recorder to remain untouched (200 default), got %d", w.Code)
		}
	})

	t.Run("role match is case-insensitive", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/admin-only", nil)
		c.Set(ContextKeyRole, "Admin")

		RequireRole("admin")(c)

		if c.IsAborted() {
			t.Fatal("role matching should be case-insensitive")
		}
	})
}

func TestGetUserIDAndRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	if id := GetUserID(c); id != "" {
		t.Fatalf("expected empty user id when unset, got %q", id)
	}
	if role := GetUserRole(c); role != "" {
		t.Fatalf("expected empty role when unset, got %q", role)
	}

	c.Set(ContextKeyUserID, "u1")
	c.Set(ContextKeyRole, "analyst")

	if id := GetUserID(c); id != "u1" {
		t.Fatalf("expected u1, got %q", id)
	}
	if role := GetUserRole(c); role != "analyst" {
		t.Fatalf("expected analyst, got %q", role)
	}
}

func TestParseToken(t *testing.T) {
	const secret = "test-secret-at-least-32-characters-long"

	t.Run("valid token", func(t *testing.T) {
		claims := Claims{
			UserID: "u1",
			Email:  "u1@example.com",
			Role:   "analyst",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			},
		}
		tokenStr := signTestToken(t, secret, claims)

		got, err := ParseToken(secret, tokenStr)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if got.UserID != "u1" || got.Role != "analyst" {
			t.Fatalf("unexpected claims: %+v", got)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		tokenStr := signTestToken(t, secret, Claims{UserID: "u1"})
		if _, err := ParseToken("a-completely-different-secret-value", tokenStr); err == nil {
			t.Fatal("expected error for token signed with a different secret")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		claims := Claims{
			UserID: "u1",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			},
		}
		tokenStr := signTestToken(t, secret, claims)
		if _, err := ParseToken(secret, tokenStr); err == nil {
			t.Fatal("expected error for expired token")
		}
	})

	t.Run("garbage token", func(t *testing.T) {
		if _, err := ParseToken(secret, "not-a-jwt"); err == nil {
			t.Fatal("expected error for malformed token")
		}
	})
}

// TestWSAuth covers the /ws query-param auth gate (§ contract: WS
// /ws?token=<access_token>, invalid/missing token -> 401 before upgrade).
func TestWSAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const secret = "test-secret-at-least-32-characters-long"

	t.Run("missing token rejected with 401", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/ws", nil)

		WSAuth(secret)(c)

		if !c.IsAborted() {
			t.Fatal("expected context to be aborted when token is missing")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("invalid token rejected with 401", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/ws?token=garbage", nil)

		WSAuth(secret)(c)

		if !c.IsAborted() {
			t.Fatal("expected context to be aborted for an invalid token")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("valid token passes and sets context", func(t *testing.T) {
		tokenStr := signTestToken(t, secret, Claims{
			UserID: "u1",
			Role:   "analyst",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			},
		})

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/ws?token="+tokenStr, nil)

		WSAuth(secret)(c)

		if c.IsAborted() {
			t.Fatal("expected context not to be aborted for a valid token")
		}
		if GetUserID(c) != "u1" {
			t.Fatalf("expected user id to be set on context, got %q", GetUserID(c))
		}
	})
}
