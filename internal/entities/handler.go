package entities

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

func (h *Handler) CreateEntity(c *gin.Context) {
	var req CreateEntityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	e, err := h.svc.CreateEntity(c.Request.Context(), req)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}

	errors.Created(c, e)
}

func (h *Handler) GetEntity(c *gin.Context) {
	id := c.Param("id")
	e, err := h.svc.GetEntity(c.Request.Context(), id)
	if err != nil {
		errors.Fail(c, errors.ErrNotFound)
		return
	}

	errors.OK(c, e)
}

func (h *Handler) ListEntities(c *gin.Context) {
	search := c.Query("search")
	entType := c.Query("type")

	list, err := h.svc.ListEntities(c.Request.Context(), search, entType)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}

	errors.OK(c, list)
}

func (h *Handler) CreateRelationship(c *gin.Context) {
	var req CreateRelationshipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	r, err := h.svc.CreateRelationship(c.Request.Context(), req)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}

	errors.Created(c, r)
}

func (h *Handler) Expand(c *gin.Context) {
	var req ExpandRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	nodes, edges, err := h.svc.Expand(c.Request.Context(), req.NodeID)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}

	errors.OK(c, gin.H{
		"nodes": nodes,
		"edges": edges,
	})
}

func (h *Handler) FindPath(c *gin.Context) {
	var req PathRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	nodes, edges, err := h.svc.FindPath(c.Request.Context(), req.StartID, req.EndID)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}

	errors.OK(c, gin.H{
		"nodes": nodes,
		"edges": edges,
	})
}
