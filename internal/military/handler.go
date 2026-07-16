package military

import (
	"net/http"

	"intelligence-platform/pkg/errors"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// Units godoc - GET /api/v1/military/units
func (h *Handler) Units(c *gin.Context) {
	out, err := h.svc.Units(c.Request.Context())
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, out)
}

// Threats godoc - GET /api/v1/military/threats?classification=
func (h *Handler) Threats(c *gin.Context) {
	out, err := h.svc.Threats(c.Request.Context(), c.Query("classification"))
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, out)
}

// Missions godoc - GET /api/v1/military/missions
func (h *Handler) Missions(c *gin.Context) {
	out, err := h.svc.Missions(c.Request.Context())
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, out)
}

/* ------------------------------ Unit CRUD -------------------------------- */

func (h *Handler) CreateUnit(c *gin.Context) {
	var u Unit
	if err := c.ShouldBindJSON(&u); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.svc.CreateUnit(c.Request.Context(), &u)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.Created(c, out)
}
func (h *Handler) UpdateUnit(c *gin.Context) {
	var u Unit
	if err := c.ShouldBindJSON(&u); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.svc.UpdateUnit(c.Request.Context(), c.Param("id"), &u)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, out)
}
func (h *Handler) DeleteUnit(c *gin.Context) {
	if err := h.svc.DeleteUnit(c.Request.Context(), c.Param("id")); err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, gin.H{"deleted": c.Param("id")})
}

/* ----------------------------- Threat CRUD ------------------------------- */

func (h *Handler) CreateThreat(c *gin.Context) {
	var t Threat
	if err := c.ShouldBindJSON(&t); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.svc.CreateThreat(c.Request.Context(), &t)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.Created(c, out)
}
func (h *Handler) UpdateThreat(c *gin.Context) {
	var t Threat
	if err := c.ShouldBindJSON(&t); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.svc.UpdateThreat(c.Request.Context(), c.Param("id"), &t)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, out)
}
func (h *Handler) DeleteThreat(c *gin.Context) {
	if err := h.svc.DeleteThreat(c.Request.Context(), c.Param("id")); err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, gin.H{"deleted": c.Param("id")})
}

/* ---------------------------- Mission CRUD ------------------------------- */

func (h *Handler) CreateMission(c *gin.Context) {
	var m Mission
	if err := c.ShouldBindJSON(&m); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.svc.CreateMission(c.Request.Context(), &m)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.Created(c, out)
}
func (h *Handler) UpdateMission(c *gin.Context) {
	var m Mission
	if err := c.ShouldBindJSON(&m); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.svc.UpdateMission(c.Request.Context(), c.Param("id"), &m)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, out)
}
func (h *Handler) DeleteMission(c *gin.Context) {
	if err := h.svc.DeleteMission(c.Request.Context(), c.Param("id")); err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, gin.H{"deleted": c.Param("id")})
}

// Stats godoc - GET /api/v1/military/stats
func (h *Handler) Stats(c *gin.Context) {
	st, err := h.svc.Stats(c.Request.Context())
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, st)
}
