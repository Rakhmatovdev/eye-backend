package crypto

import "testing"

func TestHashAndCheckPassword(t *testing.T) {
	hash, err := HashPassword("Secret123!")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}
	if !CheckPassword("Secret123!", hash) {
		t.Fatal("correct password should verify")
	}
	if CheckPassword("wrong-password", hash) {
		t.Fatal("wrong password must not verify")
	}
}

func TestGenerateToken(t *testing.T) {
	tok, err := GenerateToken(16)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	if len(tok) != 32 { // 16 bytes -> 32 hex chars
		t.Fatalf("want 32 hex chars, got %d", len(tok))
	}
	other, _ := GenerateToken(16)
	if tok == other {
		t.Fatal("tokens should be unique")
	}
}
