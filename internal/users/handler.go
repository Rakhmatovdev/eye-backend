package users

import (
	"net/http"
	"strings"

	"intelligence-platform/pkg/errors"
	"intelligence-platform/pkg/pagination"

	"github.com/gin-gonic/gin"
)

// Handler handles HTTP requests for user endpoints.
type Handler struct {
	svc *Service
}

// NewHandler creates a new users handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// List godoc - GET /api/v1/users?status=&role=&search=&page=&limit=
func (h *Handler) List(c *gin.Context) {
	pg, ok := pagination.Parse(c.Query("page"), c.Query("limit"))

	filter := ListUsersFilter{
		Status: c.Query("status"),
		Role:   c.Query("role"),
		Search: c.Query("search"),
	}
	if ok {
		filter.Pg = &pg
	}

	users, total, err := h.svc.List(c.Request.Context(), filter)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, "failed to list users")
		return
	}

	if ok {
		errors.OKWithMeta(c, users, pg.ToMeta(total))
		return
	}
	errors.OK(c, users)
}

// Create godoc - POST /api/v1/users
func (h *Handler) Create(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	user, err := h.svc.Create(c.Request.Context(), req)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "duplicate") || strings.Contains(msg, "unique") || strings.Contains(msg, "already exists") {
			errors.FailMsg(c, http.StatusConflict, "a user with this email already exists")
			return
		}
		errors.FailMsg(c, http.StatusInternalServerError, "failed to create user")
		return
	}

	errors.Created(c, user)
}

// GetByID godoc - GET /api/v1/users/:id
func (h *Handler) GetByID(c *gin.Context) {
	id := c.Param("id")
	user, err := h.svc.GetByID(c.Request.Context(), id)
	if err != nil {
		errors.Fail(c, errors.ErrNotFound)
		return
	}
	errors.OK(c, user)
}

// Update godoc - PATCH /api/v1/users/:id
func (h *Handler) Update(c *gin.Context) {
	id := c.Param("id")
	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	user, err := h.svc.Update(c.Request.Context(), id, req)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, "failed to update user")
		return
	}
	errors.OK(c, user)
}

// Delete godoc - DELETE /api/v1/users/:id
func (h *Handler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.Delete(c.Request.Context(), id); err != nil {
		errors.Fail(c, errors.ErrNotFound)
		return
	}
	errors.OK(c, gin.H{"message": "user deleted"})
}

// Suspend godoc - POST /api/v1/users/:id/suspend
func (h *Handler) Suspend(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.Suspend(c.Request.Context(), id); err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, "failed to suspend user")
		return
	}
	errors.OK(c, gin.H{"message": "user suspended"})
}

// Activate godoc - POST /api/v1/users/:id/activate
func (h *Handler) Activate(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.Activate(c.Request.Context(), id); err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, "failed to activate user")
		return
	}
	errors.OK(c, gin.H{"message": "user activated"})
}
