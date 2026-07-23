package analytics

import (
	apperrors "intelligence-platform/pkg/errors"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// GetPatterns godoc - GET /api/v1/analytics/patterns
// Computes patterns server-side, on request, from live data (no cron, no ML).
func (h *Handler) GetPatterns(c *gin.Context) {
	patterns, err := h.svc.DetectPatterns(c.Request.Context())
	if err != nil {
		apperrors.Internal(c, err)
		return
	}
	apperrors.OK(c, gin.H{"patterns": patterns})
}
