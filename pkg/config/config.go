package config

import (
	"fmt"
	"strings"

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

	return cfg, nil
}
