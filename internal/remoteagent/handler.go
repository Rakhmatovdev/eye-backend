package remoteagent

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

func (h *Handler) ListAgents(c *gin.Context) {
	list, err := h.svc.ListAgents(c.Request.Context())
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, list)
}

func (h *Handler) GetAgent(c *gin.Context) {
	id := c.Param("id")
	agent, err := h.svc.GetAgent(c.Request.Context(), id)
	if err != nil {
		errors.Fail(c, errors.ErrNotFound)
		return
	}
	errors.OK(c, agent)
}

func (h *Handler) CreateCommand(c *gin.Context) {
	agentID := c.Param("id")
	var req CreateCommandRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	userID := mw.GetUserID(c)
	cmd, err := h.svc.CreateCommand(c.Request.Context(), agentID, req.Command, userID)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.Created(c, cmd)
}

func (h *Handler) ListCommands(c *gin.Context) {
	agentID := c.Param("id")
	list, err := h.svc.ListCommands(c.Request.Context(), agentID)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, list)
}
