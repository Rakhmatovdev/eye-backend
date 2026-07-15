package middleware

import (
	"sync"
	"time"
)

// In-memory login lockout tracking. Single-instance only; for a multi-replica
// deployment this would move to a shared store. Replaces the previous
// Redis-backed implementation.

const (
	maxLoginFailures = 5
	loginLockWindow  = 15 * time.Minute
)

type loginAttempt struct {
	failures  int
	windowEnd time.Time
	lockUntil time.Time
}

var (
	loginMu       sync.Mutex
	loginAttempts = make(map[string]*loginAttempt)
)

// CheckLoginLockout reports whether an identifier is currently locked out and,
// if so, how much time remains.
func CheckLoginLockout(identifier string) (bool, time.Duration, error) {
	loginMu.Lock()
	defer loginMu.Unlock()

	a := loginAttempts[identifier]
	if a == nil {
		return false, 0, nil
	}
	if now := time.Now(); now.Before(a.lockUntil) {
		return true, time.Until(a.lockUntil), nil
	}
	return false, 0, nil
}

// RecordFailedLogin increments the failed-login counter for an identifier and
// returns true if this failure triggered a lockout.
func RecordFailedLogin(identifier string) (bool, error) {
	loginMu.Lock()
	defer loginMu.Unlock()

	now := time.Now()
	a := loginAttempts[identifier]
	if a == nil || now.After(a.windowEnd) {
		a = &loginAttempt{windowEnd: now.Add(loginLockWindow)}
		loginAttempts[identifier] = a
	}

	a.failures++
	if a.failures >= maxLoginFailures {
		a.lockUntil = now.Add(loginLockWindow)
		a.failures = 0
		return true, nil
	}
	return false, nil
}

// ClearFailedLogins resets the counter after a successful login.
func ClearFailedLogins(identifier string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	delete(loginAttempts, identifier)
}
