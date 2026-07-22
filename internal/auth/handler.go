package auth

import (
	stderrors "errors"
	"net/http"

	"intelligence-platform/internal/audit"
	"intelligence-platform/pkg/errors"
	mw "intelligence-platform/pkg/middleware"

	"github.com/gin-gonic/gin"
)

// Handler handles HTTP requests for auth endpoints.
type Handler struct {
	svc   *Service
	audit *audit.Service
}

// NewHandler creates a new auth handler.
func NewHandler(svc *Service, auditSvc *audit.Service) *Handler {
	return &Handler{svc: svc, audit: auditSvc}
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
	locked, remaining, _ := mw.CheckLoginLockout(req.Email)
	if locked {
		errors.FailMsg(c, http.StatusTooManyRequests,
			"account locked due to too many failed attempts, try again in "+remaining.String())
		return
	}

	resp, err := h.svc.Login(c.Request.Context(), req.Email, req.Password, req.OTP)
	if err != nil {
		// Record failed attempt
		h.logAudit(c, req.Email, "login", "failure")
		lockedOut, _ := mw.RecordFailedLogin(req.Email)
		if lockedOut {
			errors.FailMsg(c, http.StatusTooManyRequests, "too many failed attempts, account locked for 15 minutes")
		} else {
			errors.FailMsg(c, http.StatusUnauthorized, err.Error())
		}
		return
	}

	// MFA challenge — password was correct but a TOTP code is still required.
	if resp.MFARequired {
		errors.OK(c, resp)
		return
	}

	// Clear failed login counter on success
	mw.ClearFailedLogins(req.Email)
	h.logAudit(c, resp.User.ID, "login", "success")

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

	h.logAudit(c, userID, "logout", "success")
	errors.OK(c, gin.H{"message": "logged out successfully"})
}

// ChangePassword godoc
// POST /api/v1/auth/change-password
func (h *Handler) ChangePassword(c *gin.Context) {
	userID := mw.GetUserID(c)
	if userID == "" {
		errors.Abort(c, errors.ErrUnauthorized)
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.svc.ChangePassword(c.Request.Context(), userID, req.CurrentPassword, req.NewPassword); err != nil {
		h.logAudit(c, userID, "change_password", "failure")
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	h.logAudit(c, userID, "change_password", "success")
	errors.OK(c, gin.H{"message": "password changed successfully"})
}

// ForgotPassword godoc
// POST /api/v1/auth/forgot-password
func (h *Handler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	if locked, remaining, _ := mw.CheckForgotPasswordLockout(req.Email); locked {
		errors.FailMsg(c, http.StatusTooManyRequests,
			"too many reset requests, try again in "+remaining.String())
		return
	}
	mw.RecordForgotPasswordAttempt(req.Email)

	resp, err := h.svc.ForgotPassword(c.Request.Context(), req.Email)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, "failed to process request")
		return
	}

	h.logAudit(c, req.Email, "forgot_password", "requested")
	errors.OK(c, resp)
}

// ResetPassword godoc
// POST /api/v1/auth/reset-password
func (h *Handler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.svc.ResetPassword(c.Request.Context(), req.Token, req.NewPassword); err != nil {
		h.logAudit(c, "", "reset_password", "failure")
		// Only the invalid-token error may reach the client verbatim; anything
		// else is internal detail (e.g. a DB error) that must not be echoed.
		if stderrors.Is(err, ErrInvalidResetToken) {
			errors.FailMsg(c, http.StatusBadRequest, err.Error())
		} else {
			errors.FailMsg(c, http.StatusInternalServerError, "failed to reset password")
		}
		return
	}

	h.logAudit(c, "", "reset_password", "success")
	errors.OK(c, gin.H{"message": "password reset successfully"})
}

// EnrollMFA godoc
// POST /api/v1/auth/mfa/enroll
func (h *Handler) EnrollMFA(c *gin.Context) {
	userID := mw.GetUserID(c)
	if userID == "" {
		errors.Abort(c, errors.ErrUnauthorized)
		return
	}
	resp, err := h.svc.EnrollMFA(c.Request.Context(), userID)
	if err != nil {
		errors.Internal(c, err)
		return
	}
	errors.OK(c, resp)
}

// VerifyMFA godoc
// POST /api/v1/auth/mfa/verify
func (h *Handler) VerifyMFA(c *gin.Context) {
	userID := mw.GetUserID(c)
	if userID == "" {
		errors.Abort(c, errors.ErrUnauthorized)
		return
	}
	var req MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.svc.VerifyMFA(c.Request.Context(), userID, req.OTP); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	h.logAudit(c, userID, "mfa_enable", "success")
	errors.OK(c, gin.H{"message": "MFA enabled"})
}

// DisableMFA godoc
// POST /api/v1/auth/mfa/disable
func (h *Handler) DisableMFA(c *gin.Context) {
	userID := mw.GetUserID(c)
	if userID == "" {
		errors.Abort(c, errors.ErrUnauthorized)
		return
	}
	var req MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.svc.DisableMFA(c.Request.Context(), userID, req.OTP); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	h.logAudit(c, userID, "mfa_disable", "success")
	errors.OK(c, gin.H{"message": "MFA disabled"})
}

// logAudit best-effort records an authentication event.
func (h *Handler) logAudit(c *gin.Context, userID, action, result string) {
	if h.audit == nil {
		return
	}
	_ = h.audit.Log(c.Request.Context(), userID, action, "/api/v1/auth/"+action, c.ClientIP(), result)
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
