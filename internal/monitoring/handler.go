package monitoring

import (
	"intelligence-platform/pkg/errors"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) GetMetrics(c *gin.Context) {
	metrics := h.svc.GetMetrics()
	errors.OK(c, metrics)
}

func (h *Handler) GetServices(c *gin.Context) {
	services := h.svc.GetServiceStatus()
	errors.OK(c, services)
}
