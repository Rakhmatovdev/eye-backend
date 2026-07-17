package sensors

import (
	"net/http"
	"strconv"

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

// List godoc - GET /api/v1/sensors?type=&status=
func (h *Handler) List(c *gin.Context) {
	list, err := h.svc.List(c.Request.Context(), c.Query("type"), c.Query("status"))
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, list)
}

// Get godoc - GET /api/v1/sensors/:id
func (h *Handler) Get(c *gin.Context) {
	out, err := h.svc.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		errors.Fail(c, errors.ErrNotFound)
		return
	}
	errors.OK(c, out)
}

// Detections godoc - GET /api/v1/sensors/detections?sensor_id=&entity_id=&limit=&page=
// `limit` alone keeps its legacy "simple cap" meaning (up to 500, no meta) so
// existing callers (the live feed) are unaffected. Passing `page` opts into
// true page/limit pagination with a `meta {page,limit,total}` envelope.
func (h *Handler) Detections(c *gin.Context) {
	sensorID := c.Query("sensor_id")
	entityID := c.Query("entity_id")

	if pageStr := c.Query("page"); pageStr != "" {
		pg, _ := pagination.Parse(pageStr, c.Query("limit"))
		list, total, err := h.svc.DetectionsPaginated(c.Request.Context(), sensorID, entityID, pg)
		if err != nil {
			errors.FailMsg(c, http.StatusInternalServerError, err.Error())
			return
		}
		errors.OKWithMeta(c, list, pg.ToMeta(total))
		return
	}

	limit, _ := strconv.ParseInt(c.Query("limit"), 10, 64)
	list, err := h.svc.Detections(c.Request.Context(), sensorID, entityID, limit)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, list)
}

// Create godoc - POST /api/v1/sensors (admin)
func (h *Handler) Create(c *gin.Context) {
	var in SensorInput
	if err := c.ShouldBindJSON(&in); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.svc.Create(c.Request.Context(), in)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.Created(c, out)
}

// Update godoc - PUT /api/v1/sensors/:id (admin)
func (h *Handler) Update(c *gin.Context) {
	var in SensorInput
	if err := c.ShouldBindJSON(&in); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.svc.Update(c.Request.Context(), c.Param("id"), in)
	if err != nil {
		errors.Fail(c, errors.ErrNotFound)
		return
	}
	errors.OK(c, out)
}

// Delete godoc - DELETE /api/v1/sensors/:id (admin)
func (h *Handler) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), c.Param("id")); err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, gin.H{"deleted": c.Param("id")})
}

// Stats godoc - GET /api/v1/sensors/stats
func (h *Handler) Stats(c *gin.Context) {
	st, err := h.svc.Stats(c.Request.Context())
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, err.Error())
		return
	}
	errors.OK(c, st)
}
