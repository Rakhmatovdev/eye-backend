package auth

import (
	"time"
)

// User represents a platform user.
type User struct {
	ID             string    `json:"id" db:"id"`
	Email          string    `json:"email" db:"email"`
	PasswordHash   string    `json:"-" db:"password_hash"`
	FirstName      string    `json:"first_name" db:"first_name"`
	LastName       string    `json:"last_name" db:"last_name"`
	Role           string    `json:"role" db:"role"`
	ClearanceLevel int       `json:"clearance_level" db:"clearance_level"`
	Status         string    `json:"status" db:"status"`
	LastLogin      *time.Time `json:"last_login,omitempty" db:"last_login"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

// LoginRequest is the body for POST /auth/login.
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

// LoginResponse is returned on successful login.
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // seconds
	User         *User  `json:"user"`
}

// RefreshRequest is the body for POST /auth/refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// TokenPair holds both access and refresh tokens.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
}
