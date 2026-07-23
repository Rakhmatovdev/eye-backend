package config

import (
	"fmt"
	"strings"

	"intelligence-platform/pkg/email"

	"github.com/spf13/viper"
)

// Config holds all application configuration.
type Config struct {
	Port             string   `mapstructure:"PORT"`
	MongoURI         string   `mapstructure:"MONGO_URI"`
	DBName           string   `mapstructure:"DB_NAME"`
	JWTSecret        string   `mapstructure:"JWT_SECRET"`
	JWTRefreshSecret string   `mapstructure:"JWT_REFRESH_SECRET"`
	CORSOrigins      []string `mapstructure:"CORS_ORIGINS"`
	Environment      string   `mapstructure:"ENVIRONMENT"`

	// AI assistant (multi-provider). Provider: auto | local | claude | off.
	// "local" uses a local Ollama server (no API key needed); "claude" uses the
	// Anthropic API; "auto" tries local, then claude, then a simulated fallback.
	AIProvider      string `mapstructure:"AI_PROVIDER"`
	OllamaURL       string `mapstructure:"OLLAMA_URL"`
	OllamaModel     string `mapstructure:"OLLAMA_MODEL"`
	AnthropicAPIKey string `mapstructure:"ANTHROPIC_API_KEY"`
	AnthropicModel  string `mapstructure:"ANTHROPIC_MODEL"`

	// Outbound email (password reset). When SMTPHost is empty, the email
	// package falls back to a no-op sender that only logs (no real
	// dependency required for local dev/tests).
	SMTPHost     string `mapstructure:"SMTP_HOST"`
	SMTPPort     string `mapstructure:"SMTP_PORT"`
	SMTPUsername string `mapstructure:"SMTP_USERNAME"`
	SMTPPassword string `mapstructure:"SMTP_PASSWORD"`
	SMTPFrom     string `mapstructure:"SMTP_FROM"`

	// AppBaseURL is the frontend origin used to build links embedded in
	// emails (e.g. the password-reset link).
	AppBaseURL string `mapstructure:"APP_BASE_URL"`
}

// Load reads configuration from .env file and environment variables.
func Load() (*Config, error) {
	viper.SetConfigFile(".env")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	// Set defaults
	viper.SetDefault("PORT", "8080")
	viper.SetDefault("ENVIRONMENT", "development")
	viper.SetDefault("DB_NAME", "intelligence_db")
	viper.SetDefault("MONGO_URI", "mongodb://localhost:27017")
	viper.SetDefault("JWT_SECRET", "default-secret-change-in-production-32chars")
	viper.SetDefault("JWT_REFRESH_SECRET", "default-refresh-secret-change-in-production-32chars")
	viper.SetDefault("AI_PROVIDER", "auto")
	viper.SetDefault("OLLAMA_URL", "http://localhost:11434")
	viper.SetDefault("OLLAMA_MODEL", "llama3.2")
	viper.SetDefault("ANTHROPIC_MODEL", "claude-opus-4-8")
	viper.SetDefault("SMTP_PORT", "587")
	viper.SetDefault("APP_BASE_URL", email.DefaultAppBaseURL)

	if err := viper.ReadInConfig(); err != nil {
		// Not fatal — env vars may be set directly
		fmt.Printf("Warning: could not read .env file: %v\n", err)
	}

	cfg := &Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Parse CORS origins from comma-separated string
	originsRaw := viper.GetString("CORS_ORIGINS")
	if originsRaw != "" {
		parts := strings.Split(originsRaw, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				cfg.CORSOrigins = append(cfg.CORSOrigins, trimmed)
			}
		}
	}

	if len(cfg.CORSOrigins) == 0 {
		cfg.CORSOrigins = []string{"http://localhost:3000", "http://localhost:5173"}
	}

	// In production, refuse to boot with the built-in default JWT secrets.
	if cfg.IsProduction() {
		if isWeakSecret(cfg.JWTSecret) || isWeakSecret(cfg.JWTRefreshSecret) {
			return nil, fmt.Errorf("refusing to start in production with a default/weak JWT secret; set strong JWT_SECRET and JWT_REFRESH_SECRET (>= 32 chars)")
		}
	}

	return cfg, nil
}

// IsProduction reports whether the app is running in a production environment.
func (c *Config) IsProduction() bool {
	return strings.EqualFold(c.Environment, "production") || strings.EqualFold(c.Environment, "prod")
}

// IsDevelopment reports whether the app is running in a development environment.
func (c *Config) IsDevelopment() bool {
	return strings.EqualFold(c.Environment, "development") || strings.EqualFold(c.Environment, "dev")
}

func isWeakSecret(s string) bool {
	return len(s) < 32 || strings.Contains(s, "change-in-production") || strings.HasPrefix(s, "default-")
}
