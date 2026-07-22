package middleware

import "testing"

func TestForgotPasswordRateLimit(t *testing.T) {
	id := "forgot-test@example.com"

	for i := 0; i < maxForgotPasswordRequests; i++ {
		if locked, _, _ := CheckForgotPasswordLockout(id); locked {
			t.Fatalf("should not be locked before quota exhausted (attempt %d)", i+1)
		}
		RecordForgotPasswordAttempt(id)
	}

	locked, remaining, _ := CheckForgotPasswordLockout(id)
	if !locked {
		t.Fatal("expected lockout after exceeding quota")
	}
	if remaining <= 0 {
		t.Fatalf("expected positive remaining window, got %v", remaining)
	}
}
