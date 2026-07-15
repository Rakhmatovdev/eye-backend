package auth

import (
	"context"
	"fmt"
	"time"

	"intelligence-platform/pkg/crypto"
	"intelligence-platform/pkg/middleware"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 7 * 24 * time.Hour
	refreshKeyPfx   = "refresh:"
)

// Service handles authentication business logic.
type Service struct {
	db               *pgxpool.Pool
	rdb              *redis.Client
	jwtSecret        string
	jwtRefreshSecret string
	log              *zap.Logger
}

// NewService creates a new auth service.
func NewService(db *pgxpool.Pool, rdb *redis.Client, jwtSecret, jwtRefreshSecret string, log *zap.Logger) *Service {
	return &Service{
		db:               db,
		rdb:              rdb,
		jwtSecret:        jwtSecret,
		jwtRefreshSecret: jwtRefreshSecret,
		log:              log,
	}
}

// Login validates credentials and returns a token pair.
func (s *Service) Login(ctx context.Context, email, password string) (*LoginResponse, error) {
	user, err := s.getUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if !crypto.CheckPassword(password, user.PasswordHash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	if user.Status != "active" {
		return nil, fmt.Errorf("account is %s", user.Status)
	}

	// Update last login
	_, _ = s.db.Exec(ctx, `UPDATE users SET last_login = NOW() WHERE id = $1`, user.ID)

	tokens, err := s.generateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Store refresh token in Redis
	if err := s.storeRefreshToken(ctx, user.ID, tokens.RefreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    int(accessTokenTTL.Seconds()),
		User:         user,
	}, nil
}

// Refresh validates a refresh token and issues a new token pair.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*LoginResponse, error) {
	claims := &middleware.Claims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(s.jwtRefreshSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Verify token exists in Redis
	stored, err := s.rdb.Get(ctx, refreshKeyPfx+claims.UserID).Result()
	if err != nil || stored != refreshToken {
		return nil, fmt.Errorf("refresh token expired or revoked")
	}

	user, err := s.getUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	tokens, err := s.generateTokenPair(user)
	if err != nil {
		return nil, err
	}

	if err := s.storeRefreshToken(ctx, user.ID, tokens.RefreshToken); err != nil {
		return nil, err
	}

	return &LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    int(accessTokenTTL.Seconds()),
		User:         user,
	}, nil
}

// Logout revokes the user's refresh token.
func (s *Service) Logout(ctx context.Context, userID string) error {
	return s.rdb.Del(ctx, refreshKeyPfx+userID).Err()
}

// GetMe returns the full user profile for a given user ID.
func (s *Service) GetMe(ctx context.Context, userID string) (*User, error) {
	return s.getUserByID(ctx, userID)
}

// generateTokenPair creates access + refresh JWT tokens.
func (s *Service) generateTokenPair(user *User) (*TokenPair, error) {
	now := time.Now()

	// Access token
	accessClaims := middleware.Claims{
		UserID:         user.ID,
		Email:          user.Email,
		Role:           user.Role,
		ClearanceLevel: user.ClearanceLevel,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenTTL)),
			Issuer:    "intelligence-platform",
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessStr, err := accessToken.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return nil, err
	}

	// Refresh token
	refreshClaims := middleware.Claims{
		UserID: user.ID,
		Email:  user.Email,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(refreshTokenTTL)),
			Issuer:    "intelligence-platform",
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshStr, err := refreshToken.SignedString([]byte(s.jwtRefreshSecret))
	if err != nil {
		return nil, err
	}

	return &TokenPair{AccessToken: accessStr, RefreshToken: refreshStr}, nil
}

func (s *Service) storeRefreshToken(ctx context.Context, userID, token string) error {
	return s.rdb.Set(ctx, refreshKeyPfx+userID, token, refreshTokenTTL).Err()
}

func (s *Service) getUserByEmail(ctx context.Context, email string) (*User, error) {
	user := &User{}
	row := s.db.QueryRow(ctx,
		`SELECT id, email, password_hash, first_name, last_name, role, clearance_level, status, last_login, created_at
		 FROM users WHERE email = $1`, email)
	err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
		&user.Role, &user.ClearanceLevel, &user.Status, &user.LastLogin, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Service) getUserByID(ctx context.Context, id string) (*User, error) {
	user := &User{}
	row := s.db.QueryRow(ctx,
		`SELECT id, email, password_hash, first_name, last_name, role, clearance_level, status, last_login, created_at
		 FROM users WHERE id = $1`, id)
	err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
		&user.Role, &user.ClearanceLevel, &user.Status, &user.LastLogin, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}
