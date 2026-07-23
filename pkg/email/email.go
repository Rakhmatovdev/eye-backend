// Package email sends transactional email (currently: password-reset
// links). It picks an SMTP-backed sender when SMTP_HOST is configured, and
// otherwise falls back to a no-op sender that just logs that a message
// would have been sent — preserving the pre-integration behaviour where
// forgot-password worked end-to-end without any mail server configured
// (dev/test), just without a real email landing in an inbox.
package email

import (
	"fmt"
	"net/smtp"

	"go.uber.org/zap"
)

// Sender sends a plain-text email. Implementations: SMTPSender (real
// delivery via net/smtp, no external dependencies) and NoopSender
// (dev/test fallback that only logs).
type Sender interface {
	Send(to, subject, textBody string) error
}

// DefaultAppBaseURL is used when APP_BASE_URL is not configured.
const DefaultAppBaseURL = "http://localhost:3001"

// Config configures the SMTP sender.
type Config struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
}

// NewSender selects an implementation based on cfg: an SMTPSender when
// SMTPHost is set, otherwise a logging NoopSender. This is the single
// decision point for "is email actually configured" — callers never need to
// branch on config themselves.
func NewSender(cfg Config, log *zap.Logger) Sender {
	if cfg.SMTPHost == "" {
		return &NoopSender{log: log}
	}
	return &SMTPSender{cfg: cfg}
}

// SMTPSender sends email via net/smtp (stdlib only, no new dependencies).
type SMTPSender struct {
	cfg Config
}

// NewSMTPSender constructs an SMTPSender directly (mainly for tests; normal
// callers should go through NewSender).
func NewSMTPSender(cfg Config) *SMTPSender { return &SMTPSender{cfg: cfg} }

// Send delivers a plain-text email via the configured SMTP server.
// Authentication is skipped when no username is configured (some internal
// relays allow anonymous submission).
func (s *SMTPSender) Send(to, subject, textBody string) error {
	if s.cfg.SMTPHost == "" {
		return fmt.Errorf("email: SMTP_HOST is not configured")
	}

	port := s.cfg.SMTPPort
	if port == "" {
		port = "587"
	}
	addr := fmt.Sprintf("%s:%s", s.cfg.SMTPHost, port)

	from := s.cfg.SMTPFrom
	if from == "" {
		from = s.cfg.SMTPUsername
	}
	if from == "" {
		return fmt.Errorf("email: SMTP_FROM or SMTP_USERNAME must be set")
	}

	var auth smtp.Auth
	if s.cfg.SMTPUsername != "" {
		auth = smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	}

	return smtp.SendMail(addr, auth, from, []string{to}, buildMessage(from, to, subject, textBody))
}

// buildMessage renders a minimal RFC 5322 plain-text message.
func buildMessage(from, to, subject, body string) []byte {
	return []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\n%s\r\n",
		from, to, subject, body,
	))
}

// NoopSender logs that an email would have been sent instead of actually
// sending it. Used when SMTP is not configured (local dev, tests, or any
// environment that hasn't set SMTP_HOST). It deliberately does not log the
// message body — callers (e.g. the password-reset flow) may put sensitive
// tokens/links in the body, and that already has its own, environment-gated
// logging when appropriate.
type NoopSender struct {
	log *zap.Logger
}

// Send always succeeds; it only logs that email delivery was skipped.
func (n *NoopSender) Send(to, subject, textBody string) error {
	if n.log != nil {
		n.log.Info("email not sent: SMTP is not configured (no-op sender)",
			zap.String("to", to), zap.String("subject", subject))
	}
	return nil
}
