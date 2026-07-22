package ai

import (
	"net/http"
	"strconv"

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

// Chat godoc - POST /api/v1/ai/chat
// Every successful exchange is saved to the `ai_chats` collection
// (best-effort — a persistence failure never fails the chat response).
func (h *Handler) Chat(c *gin.Context) {
	var req ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	resp := h.svc.Chat(c.Request.Context(), req)
	h.svc.SaveChat(c.Request.Context(), mw.GetUserID(c), req.Message, resp.Reply, resp.Source)

	errors.OK(c, resp)
}

// History godoc - GET /api/v1/ai/history?limit=50 (auth)
// Returns the current user's most recent chat exchanges, oldest-first.
func (h *Handler) History(c *gin.Context) {
	userID := mw.GetUserID(c)
	if userID == "" {
		errors.Abort(c, errors.ErrUnauthorized)
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	list, err := h.svc.History(c.Request.Context(), userID, limit)
	if err != nil {
		errors.Internal(c, err)
		return
	}

	errors.OK(c, list)
}
