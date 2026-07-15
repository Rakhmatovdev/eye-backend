package cases

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

func (h *Handler) Create(c *gin.Context) {
	var req CreateCaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	userID := mw.GetUserID(c)
	res, err := h.svc.Create(c.Request.Context(), userID, req)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}

	errors.Created(c, res)
}

func (h *Handler) List(c *gin.Context) {
	userID := mw.GetUserID(c)
	list, err := h.svc.List(c.Request.Context(), userID)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
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

func (h *Handler) GetEntities(c *gin.Context) {
	id := c.Param("id")
	list, err := h.svc.GetEntities(c.Request.Context(), id)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}

	errors.OK(c, list)
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
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}

	errors.OK(c, gin.H{"message": "entity added to case"})
}
