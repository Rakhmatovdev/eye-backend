package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

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
