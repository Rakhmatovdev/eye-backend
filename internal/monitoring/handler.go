package monitoring

import (
	"intelligence-platform/pkg/errors"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc  *Service
	hist *History
}

func NewHandler(svc *Service, hist *History) *Handler {
	return &Handler{svc: svc, hist: hist}
}

func (h *Handler) GetMetrics(c *gin.Context) {
	metrics := h.svc.GetMetrics()
	errors.OK(c, metrics)
}

// GetMetricsHistory returns the buffered metrics time series, oldest-first,
// so the admin panel can draw charts (GET /monitoring/metrics/history).
func (h *Handler) GetMetricsHistory(c *gin.Context) {
	errors.OK(c, h.hist.Snapshot())
}

func (h *Handler) GetServices(c *gin.Context) {
	services := h.svc.GetServiceStatus()
	errors.OK(c, services)
}

func (h *Handler) GetDataSources(c *gin.Context) {
	errors.OK(c, h.svc.GetDataSources())
}
