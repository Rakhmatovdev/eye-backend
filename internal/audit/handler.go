package audit

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"intelligence-platform/pkg/errors"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) List(c *gin.Context) {
	search := c.Query("search")
	action := c.Query("action")

	logs, err := h.svc.List(c.Request.Context(), search, action)
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, "failed to get audit logs")
		return
	}

	errors.OK(c, logs)
}

func (h *Handler) Export(c *gin.Context) {
	logs, err := h.svc.List(c.Request.Context(), "", "")
	if err != nil {
		errors.FailMsg(c, http.StatusInternalServerError, "failed to export logs")
		return
	}

	c.Header("Content-Disposition", "attachment; filename=audit_logs.csv")
	c.Header("Content-Type", "text/csv")

	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	writer.Write([]string{"ID", "User ID", "Action", "Resource", "IP Address", "Result", "Hash", "Timestamp"})
	for _, l := range logs {
		writer.Write([]string{
			strconv.Itoa(l.ID),
			l.UserID,
			l.Action,
			l.Resource,
			l.IP,
			l.Result,
			l.Hash,
			l.Timestamp.Format(time.RFC3339),
		})
	}
}
