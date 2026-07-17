package middleware

import (
	"testing"
	"time"
)

func TestLoginLockout(t *testing.T) {
	id := "lockout-test@example.com"
	ClearFailedLogins(id)

	for i := 0; i < maxLoginFailures-1; i++ {
		if locked, _ := RecordFailedLogin(id); locked {
			t.Fatalf("locked out too early at attempt %d", i+1)
		}
	}
	// The final allowed failure should trigger the lockout.
	if locked, _ := RecordFailedLogin(id); !locked {
		t.Fatalf("expected lockout on attempt %d", maxLoginFailures)
	}

	if locked, _, _ := CheckLoginLockout(id); !locked {
		t.Fatal("account should be locked")
	}

	ClearFailedLogins(id)
	if locked, _, _ := CheckLoginLockout(id); locked {
		t.Fatal("clear should reset lockout")
	}
}

// TestLoginLockoutExpiry verifies that a lockout is lifted once its
// lockUntil timestamp is in the past. Since loginLockWindow is a 15-minute
// const, we can't wait for a real-time expiry in a unit test, so this
// white-box test (same package) rewinds the internal lockUntil timestamp to
// simulate the passage of time.
func TestLoginLockoutExpiry(t *testing.T) {
	id := "expiry-test@example.com"
	ClearFailedLogins(id)
	defer ClearFailedLogins(id)

	for i := 0; i < maxLoginFailures; i++ {
		RecordFailedLogin(id)
	}

	locked, remaining, _ := CheckLoginLockout(id)
	if !locked {
		t.Fatal("expected account to be locked after max failures")
	}
	if remaining <= 0 {
		t.Fatalf("expected positive remaining lockout duration, got %v", remaining)
	}

	loginMu.Lock()
	loginAttempts[id].lockUntil = time.Now().Add(-time.Second)
	loginMu.Unlock()

	if locked, _, _ := CheckLoginLockout(id); locked {
		t.Fatal("expected lockout to have expired once lockUntil is in the past")
	}
}
