package cases

import (
	stderrors "errors"
	"net/http"
	"time"

	"intelligence-platform/pkg/errors"
	mw "intelligence-platform/pkg/middleware"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Create(c *gin.Context) {
	var req CreateCaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	userID := mw.GetUserID(c)
	res, err := h.svc.Create(c.Request.Context(), userID, req)
	if err != nil {
		errors.Internal(c, err)
		return
	}

	errors.Created(c, res)
}

func (h *Handler) List(c *gin.Context) {
	userID := mw.GetUserID(c)
	list, err := h.svc.List(c.Request.Context(), userID)
	if err != nil {
		errors.Internal(c, err)
		return
	}

	errors.OK(c, list)
}

func (h *Handler) Get(c *gin.Context) {
	id := c.Param("id")
	res, err := h.svc.Get(c.Request.Context(), id)
	if err != nil {
		errors.Fail(c, errors.ErrNotFound)
		return
	}

	errors.OK(c, res)
}

// Update godoc - PATCH /api/v1/cases/:id {title?,description?,status?}
func (h *Handler) Update(c *gin.Context) {
	id := c.Param("id")
	var req UpdateCaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	res, err := h.svc.Update(c.Request.Context(), id, req)
	if err != nil {
		if stderrors.Is(err, mongo.ErrNoDocuments) {
			errors.Fail(c, errors.ErrNotFound)
			return
		}
		errors.Internal(c, err)
		return
	}

	errors.OK(c, res)
}

// Delete godoc - DELETE /api/v1/cases/:id
func (h *Handler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.Delete(c.Request.Context(), id); err != nil {
		if stderrors.Is(err, mongo.ErrNoDocuments) {
			errors.Fail(c, errors.ErrNotFound)
			return
		}
		errors.Internal(c, err)
		return
	}

	errors.OK(c, gin.H{"message": "case deleted"})
}

// RemoveEntity godoc - DELETE /api/v1/cases/:id/entities/:entity_id
func (h *Handler) RemoveEntity(c *gin.Context) {
	id := c.Param("id")
	entityID := c.Param("entity_id")
	if err := h.svc.RemoveEntity(c.Request.Context(), id, entityID); err != nil {
		if stderrors.Is(err, mongo.ErrNoDocuments) {
			errors.Fail(c, errors.ErrNotFound)
			return
		}
		errors.Internal(c, err)
		return
	}

	errors.OK(c, gin.H{"message": "entity removed from case"})
}

func (h *Handler) GetEntities(c *gin.Context) {
	id := c.Param("id")
	list, err := h.svc.GetEntities(c.Request.Context(), id)
	if err != nil {
		errors.Internal(c, err)
		return
	}

	errors.OK(c, list)
}

// GetReport godoc - GET /api/v1/cases/:id/report
// Assembles a full case dossier as markdown: case meta, linked entities each
// with a mini-summary, and a merged timeline (no PDF; the frontend
// renders/downloads the markdown directly).
func (h *Handler) GetReport(c *gin.Context) {
	id := c.Param("id")
	md, err := h.svc.GenerateReport(c.Request.Context(), id)
	if err != nil {
		if stderrors.Is(err, mongo.ErrNoDocuments) {
			errors.Fail(c, errors.ErrNotFound)
			return
		}
		errors.Internal(c, err)
		return
	}

	errors.OK(c, gin.H{
		"markdown":     md,
		"generated_at": time.Now(),
		"subject_id":   id,
	})
}

func (h *Handler) AddEntity(c *gin.Context) {
	id := c.Param("id")
	var req AddEntityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	userID := mw.GetUserID(c)
	err := h.svc.AddEntity(c.Request.Context(), id, req.EntityID, userID)
	if err != nil {
		errors.Internal(c, err)
		return
	}

	errors.OK(c, gin.H{"message": "entity added to case"})
}
