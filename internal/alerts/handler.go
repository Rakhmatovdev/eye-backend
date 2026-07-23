package alerts

import (
	stderrors "errors"
	"net/http"

	apperrors "intelligence-platform/pkg/errors"
	mw "intelligence-platform/pkg/middleware"
	"intelligence-platform/pkg/pagination"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// currentUser returns the authenticated caller's email, used as the
// "username" recorded on watchlist entries (created_by) and alert
// acknowledgements (ack_by) — the JWT claims carry an email, not a separate
// username field (see pkg/middleware/auth.go Claims).
func currentUser(c *gin.Context) string {
	return c.GetString(mw.ContextKeyEmail)
}

/* -------------------------------- Watchlist ------------------------------- */

// ListWatchlist godoc - GET /api/v1/watchlist
func (h *Handler) ListWatchlist(c *gin.Context) {
	list, err := h.svc.ListWatchlist(c.Request.Context())
	if err != nil {
		apperrors.Internal(c, err)
		return
	}
	apperrors.OK(c, list)
}

// AddWatchlist godoc - POST /api/v1/watchlist {entity_id, note}
// Dedupes on entity_id: a second attempt for the same entity returns 409.
func (h *Handler) AddWatchlist(c *gin.Context) {
	var req AddWatchlistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	entry, err := h.svc.AddWatchlist(c.Request.Context(), req, currentUser(c))
	if err != nil {
		switch {
		case stderrors.Is(err, ErrAlreadyWatchlisted):
			apperrors.Fail(c, apperrors.ErrConflict)
		case stderrors.Is(err, ErrEntityNotFound):
			apperrors.Fail(c, apperrors.ErrNotFound)
		default:
			apperrors.Internal(c, err)
		}
		return
	}
	apperrors.Created(c, entry)
}

// DeleteWatchlist godoc - DELETE /api/v1/watchlist/:id
func (h *Handler) DeleteWatchlist(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteWatchlist(c.Request.Context(), id); err != nil {
		if stderrors.Is(err, mongo.ErrNoDocuments) {
			apperrors.Fail(c, apperrors.ErrNotFound)
			return
		}
		apperrors.Internal(c, err)
		return
	}
	apperrors.OK(c, gin.H{"message": "removed from watchlist"})
}

/* --------------------------------- Alerts --------------------------------- */

// ListAlerts godoc - GET /api/v1/alerts?acknowledged=&severity=&limit=&page=
// Always paginated (defaults to page=1/limit=20 when the caller omits both
// query params), newest first.
func (h *Handler) ListAlerts(c *gin.Context) {
	var ackFilter *bool
	if v := c.Query("acknowledged"); v != "" {
		b := v == "true"
		ackFilter = &b
	}
	severity := c.Query("severity")

	pg, ok := pagination.Parse(c.Query("page"), c.Query("limit"))
	if !ok {
		pg = pagination.Params{Page: 1, Limit: pagination.DefaultLimit}
	}

	list, total, err := h.svc.ListAlerts(c.Request.Context(), ackFilter, severity, pg)
	if err != nil {
		apperrors.Internal(c, err)
		return
	}
	apperrors.OKWithMeta(c, list, pg.ToMeta(total))
}

// AckAlert godoc - PATCH /api/v1/alerts/:id/ack
func (h *Handler) AckAlert(c *gin.Context) {
	id := c.Param("id")
	a, err := h.svc.AckAlert(c.Request.Context(), id, currentUser(c))
	if err != nil {
		if stderrors.Is(err, mongo.ErrNoDocuments) {
			apperrors.Fail(c, apperrors.ErrNotFound)
			return
		}
		apperrors.Internal(c, err)
		return
	}
	apperrors.OK(c, a)
}

/* ------------------------------- Rule CRUD -------------------------------- */

// ListRules godoc - GET /api/v1/alerts/rules (admin)
func (h *Handler) ListRules(c *gin.Context) {
	list, err := h.svc.ListRules(c.Request.Context())
	if err != nil {
		apperrors.Internal(c, err)
		return
	}
	apperrors.OK(c, list)
}

// CreateRule godoc - POST /api/v1/alerts/rules (admin)
func (h *Handler) CreateRule(c *gin.Context) {
	var req RuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	rule, err := h.svc.CreateRule(c.Request.Context(), req)
	if err != nil {
		apperrors.Internal(c, err)
		return
	}
	apperrors.Created(c, rule)
}

// UpdateRule godoc - PUT /api/v1/alerts/rules/:id (admin)
func (h *Handler) UpdateRule(c *gin.Context) {
	id := c.Param("id")
	var req RuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	rule, err := h.svc.UpdateRule(c.Request.Context(), id, req)
	if err != nil {
		if stderrors.Is(err, mongo.ErrNoDocuments) {
			apperrors.Fail(c, apperrors.ErrNotFound)
			return
		}
		apperrors.Internal(c, err)
		return
	}
	apperrors.OK(c, rule)
}

// DeleteRule godoc - DELETE /api/v1/alerts/rules/:id (admin)
func (h *Handler) DeleteRule(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteRule(c.Request.Context(), id); err != nil {
		if stderrors.Is(err, mongo.ErrNoDocuments) {
			apperrors.Fail(c, apperrors.ErrNotFound)
			return
		}
		apperrors.Internal(c, err)
		return
	}
	apperrors.OK(c, gin.H{"message": "rule deleted"})
}
