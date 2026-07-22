package events

import (
	"net/http"

	"intelligence-platform/pkg/errors"
	"intelligence-platform/pkg/pagination"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// List godoc - GET /api/v1/timeline?type=&entity_id=&page=&limit=
func (h *Handler) List(c *gin.Context) {
	pg, ok := pagination.Parse(c.Query("page"), c.Query("limit"))
	var pgPtr *pagination.Params
	if ok {
		pgPtr = &pg
	}

	list, total, err := h.svc.List(c.Request.Context(), c.Query("type"), c.Query("entity_id"), pgPtr)
	if err != nil {
		errors.Internal(c, err)
		return
	}

	if ok {
		errors.OKWithMeta(c, list, pg.ToMeta(total))
		return
	}
	errors.OK(c, list)
}

// Create godoc - POST /api/v1/timeline
func (h *Handler) Create(c *gin.Context) {
	var req CreateEventRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	e, err := h.svc.Create(c.Request.Context(), req)
	if err != nil {
		errors.Internal(c, err)
		return
	}
	errors.Created(c, e)
}
