package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"intelligence-platform/pkg/crypto"
	"intelligence-platform/pkg/middleware"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

const mfaIssuer = "Ko'z Intelligence Platform"

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 7 * 24 * time.Hour
)

// Service handles authentication business logic.
type Service struct {
	db               *mongo.Database
	jwtSecret        string
	jwtRefreshSecret string
	log              *zap.Logger
}

// refreshToken is the stored refresh-token document (one per user, TTL-expired).
type refreshToken struct {
	UserID    string    `bson:"_id"`
	Token     string    `bson:"token"`
	ExpiresAt time.Time `bson:"expires_at"`
}

// NewService creates a new auth service.
func NewService(db *mongo.Database, jwtSecret, jwtRefreshSecret string, log *zap.Logger) *Service {
	return &Service{
		db:               db,
		jwtSecret:        jwtSecret,
		jwtRefreshSecret: jwtRefreshSecret,
		log:              log,
	}
}

func (s *Service) users() *mongo.Collection         { return s.db.Collection("users") }
func (s *Service) refreshTokens() *mongo.Collection { return s.db.Collection("refresh_tokens") }

// Login validates credentials and returns a token pair. If the account has MFA
// enabled, a valid TOTP code must be supplied; when it is missing the response
// signals mfa_required instead of issuing tokens.
func (s *Service) Login(ctx context.Context, email, password, otp string) (*LoginResponse, error) {
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

	if user.MFAEnabled {
		if otp == "" {
			return &LoginResponse{MFARequired: true}, nil
		}
		if !totp.Validate(otp, user.MFASecret) {
			return nil, fmt.Errorf("invalid MFA code")
		}
	}

	// Update last login
	_, _ = s.users().UpdateByID(ctx, user.ID, bson.M{"$set": bson.M{"last_login": time.Now()}})

	tokens, err := s.generateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

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
func (s *Service) Refresh(ctx context.Context, refreshTokenStr string) (*LoginResponse, error) {
	claims := &middleware.Claims{}
	token, err := jwt.ParseWithClaims(refreshTokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(s.jwtRefreshSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Verify token exists in store and matches
	var stored refreshToken
	err = s.refreshTokens().FindOne(ctx, bson.M{"_id": claims.UserID}).Decode(&stored)
	if err != nil || stored.Token != refreshTokenStr {
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
	_, err := s.refreshTokens().DeleteOne(ctx, bson.M{"_id": userID})
	return err
}

// GetMe returns the full user profile for a given user ID.
func (s *Service) GetMe(ctx context.Context, userID string) (*User, error) {
	return s.getUserByID(ctx, userID)
}

// ChangePassword verifies the caller's current password, stores the new
// (bcrypt-hashed) one, and revokes the user's refresh token so every other
// session is forced to re-authenticate.
func (s *Service) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	user, err := s.getUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	if !crypto.CheckPassword(currentPassword, user.PasswordHash) {
		return fmt.Errorf("current password is incorrect")
	}

	if len(newPassword) < 8 {
		return fmt.Errorf("new password must be at least 8 characters")
	}

	hash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if _, err := s.users().UpdateByID(ctx, userID, bson.M{"$set": bson.M{"password_hash": hash}}); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Revoke refresh tokens so other sessions die.
	if _, err := s.refreshTokens().DeleteOne(ctx, bson.M{"_id": userID}); err != nil {
		s.log.Error("failed to revoke refresh token after password change", zap.Error(err))
	}

	return nil
}

// EnrollMFA generates a new TOTP secret for the user (not yet enabled — the
// user must confirm with VerifyMFA) and returns the enrollment details.
func (s *Service) EnrollMFA(ctx context.Context, userID string) (*MFAEnrollResponse, error) {
	user, err := s.getUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: mfaIssuer, AccountName: user.Email})
	if err != nil {
		return nil, fmt.Errorf("failed to generate MFA secret: %w", err)
	}
	// Store the pending secret; MFAEnabled stays false until verified.
	_, err = s.users().UpdateByID(ctx, userID, bson.M{"$set": bson.M{"mfa_secret": key.Secret(), "mfa_enabled": false}})
	if err != nil {
		return nil, err
	}
	return &MFAEnrollResponse{Secret: key.Secret(), OTPAuthURL: key.URL()}, nil
}

// VerifyMFA confirms the pending TOTP secret and enables MFA for the user.
func (s *Service) VerifyMFA(ctx context.Context, userID, otp string) error {
	user, err := s.getUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if user.MFASecret == "" {
		return fmt.Errorf("no pending MFA enrollment; call enroll first")
	}
	if !totp.Validate(otp, user.MFASecret) {
		return fmt.Errorf("invalid MFA code")
	}
	_, err = s.users().UpdateByID(ctx, userID, bson.M{"$set": bson.M{"mfa_enabled": true}})
	return err
}

// DisableMFA turns off MFA after verifying a current code.
func (s *Service) DisableMFA(ctx context.Context, userID, otp string) error {
	user, err := s.getUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if !user.MFAEnabled {
		return fmt.Errorf("MFA is not enabled")
	}
	if !totp.Validate(otp, user.MFASecret) {
		return fmt.Errorf("invalid MFA code")
	}
	_, err = s.users().UpdateByID(ctx, userID, bson.M{"$set": bson.M{"mfa_enabled": false, "mfa_secret": ""}})
	return err
}

// generateTokenPair creates access + refresh JWT tokens.
func (s *Service) generateTokenPair(user *User) (*TokenPair, error) {
	now := time.Now()

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
	refreshTok := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshStr, err := refreshTok.SignedString([]byte(s.jwtRefreshSecret))
	if err != nil {
		return nil, err
	}

	return &TokenPair{AccessToken: accessStr, RefreshToken: refreshStr}, nil
}

func (s *Service) storeRefreshToken(ctx context.Context, userID, token string) error {
	doc := refreshToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(refreshTokenTTL),
	}
	_, err := s.refreshTokens().ReplaceOne(ctx, bson.M{"_id": userID}, doc, options.Replace().SetUpsert(true))
	return err
}

func (s *Service) getUserByEmail(ctx context.Context, email string) (*User, error) {
	user := &User{}
	err := s.users().FindOne(ctx, bson.M{"email": email}).Decode(user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return user, nil
}

func (s *Service) getUserByID(ctx context.Context, id string) (*User, error) {
	user := &User{}
	err := s.users().FindOne(ctx, bson.M{"_id": id}).Decode(user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return user, nil
}
