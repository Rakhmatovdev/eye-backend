package auth

import (
	"net/http"

	"intelligence-platform/pkg/errors"
	mw "intelligence-platform/pkg/middleware"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// Handler handles HTTP requests for auth endpoints.
type Handler struct {
	svc *Service
	rdb *redis.Client
}

// NewHandler creates a new auth handler.
func NewHandler(svc *Service, rdb *redis.Client) *Handler {
	return &Handler{svc: svc, rdb: rdb}
}

// Login godoc
// POST /api/v1/auth/login
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	// Check lockout
	locked, remaining, _ := mw.CheckLoginLockout(h.rdb, req.Email)
	if locked {
		errors.FailMsg(c, http.StatusTooManyRequests,
			"account locked due to too many failed attempts, try again in "+remaining.String())
		return
	}

	resp, err := h.svc.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		// Record failed attempt
		lockedOut, _ := mw.RecordFailedLogin(h.rdb, req.Email)
		if lockedOut {
			errors.FailMsg(c, http.StatusTooManyRequests, "too many failed attempts, account locked for 15 minutes")
		} else {
			errors.FailMsg(c, http.StatusUnauthorized, err.Error())
		}
		return
	}

	// Clear failed login counter on success
	mw.ClearFailedLogins(h.rdb, req.Email)

	errors.OK(c, resp)
}

// Refresh godoc
// POST /api/v1/auth/refresh
func (h *Handler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	resp, err := h.svc.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		errors.FailMsg(c, http.StatusUnauthorized, err.Error())
		return
	}

	errors.OK(c, resp)
}

// Logout godoc
// POST /api/v1/auth/logout
func (h *Handler) Logout(c *gin.Context) {
	userID := mw.GetUserID(c)
	if userID == "" {
		errors.Abort(c, errors.ErrUnauthorized)
		return
	}

	if err := h.svc.Logout(c.Request.Context(), userID); err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, "failed to logout")
		return
	}

	errors.OK(c, gin.H{"message": "logged out successfully"})
}

// Me godoc
// GET /api/v1/auth/me
func (h *Handler) Me(c *gin.Context) {
	userID := mw.GetUserID(c)
	if userID == "" {
		errors.Abort(c, errors.ErrUnauthorized)
		return
	}

	user, err := h.svc.GetMe(c.Request.Context(), userID)
	if err != nil {
		errors.Fail(c, errors.ErrNotFound)
		return
	}

	errors.OK(c, user)
}
