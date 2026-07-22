package auth

import "testing"

func TestHashResetTokenDeterministicAndDistinct(t *testing.T) {
	a := hashResetToken("token-a")
	b := hashResetToken("token-a")
	c := hashResetToken("token-b")

	if a != b {
		t.Fatal("hashing the same token twice must produce the same hash")
	}
	if a == c {
		t.Fatal("hashing different tokens must produce different hashes")
	}
	if len(a) != 64 {
		t.Fatalf("expected a 64-char hex SHA-256 digest, got %d chars", len(a))
	}
}
