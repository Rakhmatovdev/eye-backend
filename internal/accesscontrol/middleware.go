package accesscontrol

import (
	"net/http"

	"intelligence-platform/pkg/errors"
	mw "intelligence-platform/pkg/middleware"

	"github.com/gin-gonic/gin"
)

// Handler handles HTTP requests for RBAC endpoints.
type Handler struct {
	svc *RBACService
}

// NewHandler creates a new RBAC handler.
func NewHandler(svc *RBACService) *Handler {
	return &Handler{svc: svc}
}

// RequirePermission returns middleware that checks for a specific permission.
func RequirePermission(svc *RBACService, resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := mw.GetUserID(c)
		if userID == "" {
			errors.Abort(c, errors.ErrUnauthorized)
			return
		}

		// Admin role bypasses permission checks
		role := mw.GetUserRole(c)
		if role == "admin" {
			c.Next()
			return
		}

		ok, err := svc.HasPermission(c.Request.Context(), userID, resource, action)
		if err != nil || !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   gin.H{"message": "permission denied: " + resource + ":" + action},
			})
			return
		}
		c.Next()
	}
}

// ListRoles godoc - GET /api/v1/roles
func (h *Handler) ListRoles(c *gin.Context) {
	roles, err := h.svc.ListRoles(c.Request.Context())
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, "failed to list roles")
		return
	}
	errors.OK(c, roles)
}

// CreateRole godoc - POST /api/v1/roles
func (h *Handler) CreateRole(c *gin.Context) {
	var req CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	role, err := h.svc.CreateRole(c.Request.Context(), req)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, "failed to create role")
		return
	}
	errors.Created(c, role)
}

// ListPermissions godoc - GET /api/v1/permissions
func (h *Handler) ListPermissions(c *gin.Context) {
	perms, err := h.svc.ListPermissions(c.Request.Context())
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, "failed to list permissions")
		return
	}
	errors.OK(c, perms)
}

// AssignPermissions godoc - POST /api/v1/roles/:id/permissions
func (h *Handler) AssignPermissions(c *gin.Context) {
	roleID := c.Param("id")
	var req AssignPermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.svc.AssignPermissions(c.Request.Context(), roleID, req); err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, "failed to assign permissions")
		return
	}
	errors.OK(c, gin.H{"message": "permissions assigned"})
}
