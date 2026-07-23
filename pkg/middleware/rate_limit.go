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

// In-memory forgot-password request throttling, same technique as the login
// lockout above but counting every request (not just failures) since a
// forgot-password call always "succeeds" from the caller's point of view.

const (
	maxForgotPasswordRequests = 3
	forgotPasswordWindow      = time.Hour
)

type forgotPasswordAttempt struct {
	count     int
	windowEnd time.Time
}

var (
	forgotMu       sync.Mutex
	forgotAttempts = make(map[string]*forgotPasswordAttempt)
)

// CheckForgotPasswordLockout reports whether an identifier has exceeded the
// forgot-password request quota for the current window and, if so, how long
// until the window resets.
func CheckForgotPasswordLockout(identifier string) (bool, time.Duration, error) {
	forgotMu.Lock()
	defer forgotMu.Unlock()

	a := forgotAttempts[identifier]
	if a == nil {
		return false, 0, nil
	}
	now := time.Now()
	if now.After(a.windowEnd) {
		return false, 0, nil
	}
	if a.count >= maxForgotPasswordRequests {
		return true, time.Until(a.windowEnd), nil
	}
	return false, 0, nil
}

// RecordForgotPasswordAttempt increments the request counter for an
// identifier, starting a new window if the previous one has expired.
func RecordForgotPasswordAttempt(identifier string) {
	forgotMu.Lock()
	defer forgotMu.Unlock()

	now := time.Now()
	a := forgotAttempts[identifier]
	if a == nil || now.After(a.windowEnd) {
		a = &forgotPasswordAttempt{windowEnd: now.Add(forgotPasswordWindow)}
		forgotAttempts[identifier] = a
	}
	a.count++
}

// Both in-memory maps above only ever grow on write and are never cleaned up
// on their own — an identifier that fails a login once, or requests a
// password reset once, keeps its entry forever even after its window has
// long since expired. A background sweep purges anything whose window (and,
// for logins, lockout) has passed, so long-running instances don't leak
// memory in proportion to distinct identifiers seen over their lifetime.

// purgeInterval is how often the background sweep runs.
const purgeInterval = 10 * time.Minute

func init() {
	go func() {
		ticker := time.NewTicker(purgeInterval)
		defer ticker.Stop()
		for range ticker.C {
			purgeExpiredRateLimitEntries()
		}
	}()
}

// purgeExpiredRateLimitEntries deletes entries whose tracking window (and,
// for login lockouts, lockUntil) is entirely in the past. Exported logic is
// exercised indirectly via CheckLoginLockout/CheckForgotPasswordLockout,
// which already treat an expired-but-present entry as "not locked" — purging
// it is a pure memory-reclamation step and never changes observable
// lockout/quota behaviour.
func purgeExpiredRateLimitEntries() {
	now := time.Now()

	loginMu.Lock()
	for id, a := range loginAttempts {
		if now.After(a.windowEnd) && now.After(a.lockUntil) {
			delete(loginAttempts, id)
		}
	}
	loginMu.Unlock()

	forgotMu.Lock()
	for id, a := range forgotAttempts {
		if now.After(a.windowEnd) {
			delete(forgotAttempts, id)
		}
	}
	forgotMu.Unlock()
}
