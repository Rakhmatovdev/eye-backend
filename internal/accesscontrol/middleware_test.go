package accesscontrol

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mw "intelligence-platform/pkg/middleware"

	"github.com/gin-gonic/gin"
)

// TestRequirePermission_AdminBypass exercises the one branch of
// RequirePermission that is reachable without a Mongo connection: when the
// caller's role (read from the gin context via mw.GetUserRole — the same
// claims/context key set by the Auth middleware) is "admin", the middleware
// calls c.Next() immediately and never touches svc/the database. Passing a
// nil *RBACService proves that path is genuinely DB-free.
func TestRequirePermission_AdminBypass(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/entities", nil)
	c.Set(mw.ContextKeyUserID, "admin-user")
	c.Set(mw.ContextKeyRole, "admin")

	RequirePermission(nil, "entities", "read")(c)

	if c.IsAborted() {
		t.Fatal("admin role should bypass the permission check and not abort")
	}
}

// TestRequirePermission_Unauthorized covers the other DB-free branch: no
// authenticated user id in context means the request never reaches the
// (Mongo-backed) HasPermission call and is rejected with 401 up front.
func TestRequirePermission_Unauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/entities", nil)
	// No ContextKeyUserID set.

	RequirePermission(nil, "entities", "read")(c)

	if !c.IsAborted() {
		t.Fatal("missing user id should abort the request")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}
