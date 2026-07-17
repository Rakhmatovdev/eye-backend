package auth

import (
	"time"
)

// User represents a platform user.
type User struct {
	ID             string     `json:"id" bson:"_id"`
	Email          string     `json:"email" bson:"email"`
	PasswordHash   string     `json:"-" bson:"password_hash"`
	FirstName      string     `json:"first_name" bson:"first_name"`
	LastName       string     `json:"last_name" bson:"last_name"`
	Role           string     `json:"role" bson:"role"`
	ClearanceLevel int        `json:"clearance_level" bson:"clearance_level"`
	Status         string     `json:"status" bson:"status"`
	MFAEnabled     bool       `json:"mfa_enabled" bson:"mfa_enabled"`
	MFASecret      string     `json:"-" bson:"mfa_secret"`
	LastLogin      *time.Time `json:"last_login,omitempty" bson:"last_login"`
	CreatedAt      time.Time  `json:"created_at" bson:"created_at"`
}

// LoginRequest is the body for POST /auth/login.
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	OTP      string `json:"otp"` // required only when the account has MFA enabled
}

// LoginResponse is returned on successful login. When MFARequired is true the
// caller must resubmit with a valid OTP; the token fields are then empty.
type LoginResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"` // seconds
	MFARequired  bool   `json:"mfa_required,omitempty"`
	User         *User  `json:"user,omitempty"`
}

// MFAEnrollResponse is returned by POST /auth/mfa/enroll.
type MFAEnrollResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

// MFAVerifyRequest is the body for MFA verify/disable.
type MFAVerifyRequest struct {
	OTP string `json:"otp" binding:"required"`
}

// RefreshRequest is the body for POST /auth/refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// ChangePasswordRequest is the body for POST /auth/change-password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8"`
}

// TokenPair holds both access and refresh tokens.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
}
