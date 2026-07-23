package middleware

import (
	"testing"
	"time"
)

// TestPurgeExpiredRateLimitEntriesRemovesStaleLogin verifies that a login
// lockout entry whose window and lockout have both passed is deleted by the
// purge sweep (same white-box rewind technique as
// TestLoginLockoutExpiry: the purge interval is 10 minutes, so we simulate
// elapsed time by rewinding the stored timestamps instead of sleeping).
func TestPurgeExpiredRateLimitEntriesRemovesStaleLogin(t *testing.T) {
	id := "purge-login@example.com"
	ClearFailedLogins(id)
	defer ClearFailedLogins(id)

	RecordFailedLogin(id)

	loginMu.Lock()
	loginAttempts[id].windowEnd = time.Now().Add(-time.Second)
	loginAttempts[id].lockUntil = time.Now().Add(-time.Second)
	loginMu.Unlock()

	purgeExpiredRateLimitEntries()

	loginMu.Lock()
	_, exists := loginAttempts[id]
	loginMu.Unlock()
	if exists {
		t.Fatal("expected expired login attempt entry to be purged")
	}
}

// TestPurgeExpiredRateLimitEntriesKeepsActiveLogin verifies the purge sweep
// does not remove an entry whose window has not yet elapsed.
func TestPurgeExpiredRateLimitEntriesKeepsActiveLogin(t *testing.T) {
	id := "purge-active-login@example.com"
	ClearFailedLogins(id)
	defer ClearFailedLogins(id)

	RecordFailedLogin(id)

	purgeExpiredRateLimitEntries()

	loginMu.Lock()
	_, exists := loginAttempts[id]
	loginMu.Unlock()
	if !exists {
		t.Fatal("expected active login attempt entry to survive the purge")
	}
}

// TestPurgeExpiredRateLimitEntriesRemovesStaleForgotPassword mirrors the
// login case for the forgot-password quota map.
func TestPurgeExpiredRateLimitEntriesRemovesStaleForgotPassword(t *testing.T) {
	id := "purge-forgot@example.com"

	RecordForgotPasswordAttempt(id)

	forgotMu.Lock()
	forgotAttempts[id].windowEnd = time.Now().Add(-time.Second)
	forgotMu.Unlock()

	purgeExpiredRateLimitEntries()

	forgotMu.Lock()
	_, exists := forgotAttempts[id]
	forgotMu.Unlock()
	if exists {
		t.Fatal("expected expired forgot-password entry to be purged")
	}
}

// TestPurgeExpiredRateLimitEntriesKeepsActiveForgotPassword verifies the
// purge sweep does not remove a forgot-password entry whose window has not
// yet elapsed.
func TestPurgeExpiredRateLimitEntriesKeepsActiveForgotPassword(t *testing.T) {
	id := "purge-active-forgot@example.com"

	RecordForgotPasswordAttempt(id)

	purgeExpiredRateLimitEntries()

	forgotMu.Lock()
	_, exists := forgotAttempts[id]
	forgotMu.Unlock()
	if !exists {
		t.Fatal("expected active forgot-password entry to survive the purge")
	}
}
