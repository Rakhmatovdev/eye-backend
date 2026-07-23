package email

import (
	"strings"
	"testing"
)

// These tests only exercise selection/config/message-building logic — no
// network calls are made (SMTPSender.Send is never invoked).

func TestNewSenderFallsBackToNoopWhenHostEmpty(t *testing.T) {
	s := NewSender(Config{}, nil)
	if _, ok := s.(*NoopSender); !ok {
		t.Fatalf("expected *NoopSender when SMTPHost is empty, got %T", s)
	}
}

func TestNewSenderSelectsSMTPWhenHostConfigured(t *testing.T) {
	s := NewSender(Config{SMTPHost: "smtp.example.com", SMTPPort: "587"}, nil)
	if _, ok := s.(*SMTPSender); !ok {
		t.Fatalf("expected *SMTPSender when SMTPHost is set, got %T", s)
	}
}

func TestNoopSenderNeverErrors(t *testing.T) {
	s := &NoopSender{}
	if err := s.Send("a@b.com", "subject", "body with a secret token"); err != nil {
		t.Fatalf("noop sender must never error: %v", err)
	}
}

func TestSMTPSenderRequiresHost(t *testing.T) {
	s := NewSMTPSender(Config{})
	if err := s.Send("a@b.com", "subject", "body"); err == nil {
		t.Fatal("expected an error when SMTPHost is not configured")
	}
}

func TestSMTPSenderRequiresFromOrUsername(t *testing.T) {
	s := NewSMTPSender(Config{SMTPHost: "smtp.example.com", SMTPPort: "587"})
	if err := s.Send("a@b.com", "subject", "body"); err == nil {
		t.Fatal("expected an error when neither SMTP_FROM nor SMTP_USERNAME is set")
	}
}

func TestBuildMessageContainsHeadersAndBody(t *testing.T) {
	msg := string(buildMessage("from@example.com", "to@example.com", "Reset your password", "click here: http://x/y"))

	for _, want := range []string{
		"From: from@example.com",
		"To: to@example.com",
		"Subject: Reset your password",
		"click here: http://x/y",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("expected message to contain %q, got:\n%s", want, msg)
		}
	}
}
