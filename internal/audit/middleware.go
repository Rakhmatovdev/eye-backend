package audit

import (
	"context"
	"strings"

	"intelligence-platform/pkg/middleware"

	"github.com/gin-gonic/gin"
)

// Middleware records an audit-log entry for every state-changing request
// (POST/PUT/PATCH/DELETE) on authenticated routes. Auth endpoints are skipped
// because the auth handler logs login/logout explicitly (it knows the email
// before a session exists).
func Middleware(svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		switch c.Request.Method {
		case "POST", "PUT", "PATCH", "DELETE":
		default:
			return
		}
		if strings.HasPrefix(c.FullPath(), "/api/v1/auth/") {
			return
		}

		userID := middleware.GetUserID(c)
		if userID == "" {
			userID = "anonymous"
		}
		result := "success"
		if c.Writer.Status() >= 400 {
			result = "failure"
		}
		resource := c.FullPath()
		if resource == "" {
			resource = c.Request.URL.Path
		}

		// Durable write on a detached context so a cancelled request still records.
		_ = svc.Log(context.Background(), userID, strings.ToLower(c.Request.Method), resource, c.ClientIP(), result)
	}
}
