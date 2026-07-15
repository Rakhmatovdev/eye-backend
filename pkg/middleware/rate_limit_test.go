package middleware

import "testing"

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
