package entities

import (
	"errors"
	"net/http"

	apperrors "intelligence-platform/pkg/errors"
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

func (h *Handler) CreateEntity(c *gin.Context) {
	var req CreateEntityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	e, err := h.svc.CreateEntity(c.Request.Context(), req)
	if err != nil {
		apperrors.Internal(c, err)
		return
	}

	apperrors.Created(c, e)
}

func (h *Handler) GetEntity(c *gin.Context) {
	id := c.Param("id")
	e, err := h.svc.GetEntity(c.Request.Context(), id)
	if err != nil {
		apperrors.Fail(c, apperrors.ErrNotFound)
		return
	}

	apperrors.OK(c, e)
}

// ListEntities godoc - GET /api/v1/entities?search=&type=&page=&limit=
func (h *Handler) ListEntities(c *gin.Context) {
	search := c.Query("search")
	entType := c.Query("type")

	pg, ok := pagination.Parse(c.Query("page"), c.Query("limit"))
	var pgPtr *pagination.Params
	if ok {
		pgPtr = &pg
	}

	list, total, err := h.svc.ListEntities(c.Request.Context(), search, entType, pgPtr)
	if err != nil {
		apperrors.Internal(c, err)
		return
	}

	if ok {
		apperrors.OKWithMeta(c, list, pg.ToMeta(total))
		return
	}
	apperrors.OK(c, list)
}

// UpdateEntity godoc - PUT /api/v1/entities/:id
func (h *Handler) UpdateEntity(c *gin.Context) {
	id := c.Param("id")
	var req UpdateEntityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	e, err := h.svc.UpdateEntity(c.Request.Context(), id, req)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			apperrors.Fail(c, apperrors.ErrNotFound)
			return
		}
		apperrors.Internal(c, err)
		return
	}

	apperrors.OK(c, e)
}

// DeleteEntity godoc - DELETE /api/v1/entities/:id
func (h *Handler) DeleteEntity(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteEntity(c.Request.Context(), id); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			apperrors.Fail(c, apperrors.ErrNotFound)
			return
		}
		apperrors.Internal(c, err)
		return
	}

	apperrors.OK(c, gin.H{"message": "entity deleted"})
}

func (h *Handler) CreateRelationship(c *gin.Context) {
	var req CreateRelationshipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	r, err := h.svc.CreateRelationship(c.Request.Context(), req)
	if err != nil {
		apperrors.Internal(c, err)
		return
	}

	apperrors.Created(c, r)
}

// DeleteRelationship godoc - DELETE /api/v1/entities/relationship/:id
func (h *Handler) DeleteRelationship(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteRelationship(c.Request.Context(), id); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			apperrors.Fail(c, apperrors.ErrNotFound)
			return
		}
		apperrors.Internal(c, err)
		return
	}

	apperrors.OK(c, gin.H{"message": "relationship deleted"})
}

func (h *Handler) Expand(c *gin.Context) {
	var req ExpandRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	nodes, edges, err := h.svc.Expand(c.Request.Context(), req.NodeID)
	if err != nil {
		apperrors.Internal(c, err)
		return
	}

	apperrors.OK(c, gin.H{
		"nodes": nodes,
		"edges": edges,
	})
}

func (h *Handler) FindPath(c *gin.Context) {
	var req PathRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	nodes, edges, err := h.svc.FindPath(c.Request.Context(), req.StartID, req.EndID)
	if err != nil {
		apperrors.Internal(c, err)
		return
	}

	apperrors.OK(c, gin.H{
		"nodes": nodes,
		"edges": edges,
	})
}
