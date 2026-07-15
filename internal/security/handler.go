package security

import (
	"net/http"

	"intelligence-platform/pkg/errors"
	mw "intelligence-platform/pkg/middleware"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func currentUserLabel(c *gin.Context) string {
	if email := c.GetString(mw.ContextKeyEmail); email != "" {
		return email
	}
	return "Admin"
}

func (h *Handler) GetDashboard(c *gin.Context) {
	stats, err := h.svc.GetDashboardStats(c.Request.Context())
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, stats)
}

func (h *Handler) ListIncidents(c *gin.Context) {
	list, err := h.svc.ListIncidents(c.Request.Context())
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, list)
}

func (h *Handler) GetIncident(c *gin.Context) {
	id := c.Param("id")
	incident, err := h.svc.GetIncident(c.Request.Context(), id)
	if err != nil {
		errors.Fail(c, errors.ErrNotFound)
		return
	}
	errors.OK(c, incident)
}

func (h *Handler) ResolveIncident(c *gin.Context) {
	id := c.Param("id")
	err := h.svc.ResolveIncident(c.Request.Context(), id)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, gin.H{"message": "incident resolved"})
}

func (h *Handler) UpdateIncidentStatus(c *gin.Context) {
	id := c.Param("id")
	var req ResolveIncidentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.svc.UpdateIncidentStatus(c.Request.Context(), id, req.Status); err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, gin.H{"message": "incident status updated"})
}

func (h *Handler) AssignIncident(c *gin.Context) {
	id := c.Param("id")
	var req AssignIncidentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.svc.AssignIncident(c.Request.Context(), id, req.Assignee); err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, gin.H{"message": "incident assigned"})
}

func (h *Handler) AddToBlocklist(c *gin.Context) {
	var req CreateBlocklistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	item, err := h.svc.AddToBlocklist(c.Request.Context(), req, currentUserLabel(c))
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.Created(c, item)
}

func (h *Handler) ListBlocklist(c *gin.Context) {
	list, err := h.svc.ListBlocklist(c.Request.Context())
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, list)
}

func (h *Handler) RemoveFromBlocklist(c *gin.Context) {
	id := c.Param("id")
	err := h.svc.RemoveFromBlocklist(c.Request.Context(), id)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, gin.H{"message": "removed from blocklist"})
}

func (h *Handler) ListVulnerabilities(c *gin.Context) {
	list, err := h.svc.ListVulnerabilities(c.Request.Context())
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, list)
}

func (h *Handler) UpdateVulnerabilityStatus(c *gin.Context) {
	id := c.Param("id")
	var req UpdateVulnerabilityStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	v, err := h.svc.UpdateVulnerabilityStatus(c.Request.Context(), id, req.Status)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, v)
}

func (h *Handler) GetAttackMap(c *gin.Context) {
	nodes, err := h.svc.GetAttackMap(c.Request.Context())
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, nodes)
}
