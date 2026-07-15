package middleware

import (
	"net/http"
	"strings"

	"intelligence-platform/pkg/errors"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID         string `json:"user_id"`
	Email          string `json:"email"`
	Role           string `json:"role"`
	ClearanceLevel int    `json:"clearance_level"`
	jwt.RegisteredClaims
}

const (
	ContextKeyUserID         = "user_id"
	ContextKeyEmail          = "email"
	ContextKeyRole           = "role"
	ContextKeyClearanceLevel = "clearance_level"
	ContextKeyClaims         = "claims"
)

// Auth returns a middleware that validates JWT bearer tokens.
func Auth(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			errors.Abort(c, errors.ErrUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			errors.Abort(c, errors.WithDetail(errors.ErrUnauthorized, "invalid authorization header format"))
			return
		}

		tokenStr := parts[1]
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			errors.Abort(c, errors.WithDetail(errors.ErrUnauthorized, "invalid or expired token"))
			return
		}

		c.Set(ContextKeyUserID, claims.UserID)
		c.Set(ContextKeyEmail, claims.Email)
		c.Set(ContextKeyRole, claims.Role)
		c.Set(ContextKeyClearanceLevel, claims.ClearanceLevel)
		c.Set(ContextKeyClaims, claims)

		c.Next()
	}
}

// OptionalAuth attempts to authenticate but does not abort on failure.
func OptionalAuth(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.Next()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(parts[1], claims, func(t *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})

		if err == nil && token.Valid {
			c.Set(ContextKeyUserID, claims.UserID)
			c.Set(ContextKeyEmail, claims.Email)
			c.Set(ContextKeyRole, claims.Role)
			c.Set(ContextKeyClearanceLevel, claims.ClearanceLevel)
			c.Set(ContextKeyClaims, claims)
		}

		c.Next()
	}
}

// GetUserID extracts the user ID from the gin context (set by Auth middleware).
func GetUserID(c *gin.Context) string {
	v, _ := c.Get(ContextKeyUserID)
	id, _ := v.(string)
	return id
}

// GetUserRole extracts the role from the gin context.
func GetUserRole(c *gin.Context) string {
	v, _ := c.Get(ContextKeyRole)
	role, _ := v.(string)
	return role
}

// RequireRole aborts if the authenticated user does not have one of the given roles.
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role := GetUserRole(c)
		for _, r := range roles {
			if strings.EqualFold(role, r) {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"success": false,
			"error":   gin.H{"message": "insufficient role"},
		})
	}
}
