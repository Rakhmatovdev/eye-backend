package middleware

import (
	"net"
	"net/url"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CORS returns a configured CORS middleware.
//
// An origin is allowed if it is in the explicitly configured list, or — only
// when allowPrivateNetworks is set (i.e. outside production) — if it is a
// loopback or private-LAN address on any port; this lets the app be opened
// via localhost or the machine's LAN IP (e.g. from a phone) without
// hardcoding an address that changes with DHCP. In production only the
// explicit allowlist counts.
func CORS(allowedOrigins []string, allowPrivateNetworks bool) gin.HandlerFunc {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = true
	}

	cfg := cors.Config{
		AllowOriginFunc: func(origin string) bool {
			if allowed[origin] {
				return true
			}
			return allowPrivateNetworks && isLocalOrPrivateOrigin(origin)
		},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Request-ID", "X-Forwarded-For"},
		ExposeHeaders:    []string{"Content-Length", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	return cors.New(cfg)
}

// isLocalOrPrivateOrigin reports whether origin points at localhost or a
// private (RFC 1918 / loopback) IP address — safe to allow during development.
func isLocalOrPrivateOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}
