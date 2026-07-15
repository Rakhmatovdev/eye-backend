package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// RateLimit returns a Redis-backed rate limiter middleware.
// limit: max requests, window: time window.
func RateLimit(rdb *redis.Client, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		key := fmt.Sprintf("ratelimit:%s:%s", c.FullPath(), ip)

		ctx := context.Background()
		pipe := rdb.Pipeline()

		incr := pipe.Incr(ctx, key)
		pipe.Expire(ctx, key, window)

		if _, err := pipe.Exec(ctx); err != nil {
			// On Redis failure, allow the request
			c.Next()
			return
		}

		count := incr.Val()
		if count > int64(limit) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"success": false,
				"error":   gin.H{"message": "rate limit exceeded, try again later"},
			})
			return
		}

		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", int64(limit)-count))

		c.Next()
	}
}

// AuthRateLimit is a stricter rate limiter for auth endpoints (5 req/minute by default).
func AuthRateLimit(rdb *redis.Client) gin.HandlerFunc {
	return RateLimit(rdb, 20, time.Minute)
}

// CheckLoginLockout checks if an IP/email is locked out due to failed login attempts.
func CheckLoginLockout(rdb *redis.Client, identifier string) (bool, time.Duration, error) {
	key := fmt.Sprintf("lockout:%s", identifier)
	ctx := context.Background()

	ttl, err := rdb.TTL(ctx, key).Result()
	if err != nil {
		return false, 0, err
	}
	if ttl > 0 {
		return true, ttl, nil
	}
	return false, 0, nil
}

// RecordFailedLogin increments the failed login counter. Returns true if locked out.
func RecordFailedLogin(rdb *redis.Client, identifier string) (bool, error) {
	ctx := context.Background()
	key := fmt.Sprintf("loginfail:%s", identifier)
	lockKey := fmt.Sprintf("lockout:%s", identifier)

	count, err := rdb.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}
	rdb.Expire(ctx, key, 15*time.Minute)

	if count >= 5 {
		rdb.Set(ctx, lockKey, "1", 15*time.Minute)
		rdb.Del(ctx, key)
		return true, nil
	}
	return false, nil
}

// ClearFailedLogins removes the failed login counter after a successful login.
func ClearFailedLogins(rdb *redis.Client, identifier string) {
	ctx := context.Background()
	rdb.Del(ctx, fmt.Sprintf("loginfail:%s", identifier))
	rdb.Del(ctx, fmt.Sprintf("lockout:%s", identifier))
}
