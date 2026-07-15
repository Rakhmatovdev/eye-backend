package users

import (
	"time"
)

// User represents a platform user (full model).
type User struct {
	ID             string     `json:"id"`
	Email          string     `json:"email"`
	FirstName      string     `json:"first_name"`
	LastName       string     `json:"last_name"`
	Role           string     `json:"role"`
	ClearanceLevel int        `json:"clearance_level"`
	Status         string     `json:"status"`
	Department     string     `json:"department"`
	LastLogin      *time.Time `json:"last_login,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// CreateUserRequest is the body for POST /users.
type CreateUserRequest struct {
	Email          string `json:"email" binding:"required,email"`
	Password       string `json:"password" binding:"required,min=8"`
	FirstName      string `json:"first_name" binding:"required"`
	LastName       string `json:"last_name" binding:"required"`
	Role           string `json:"role" binding:"required,oneof=admin analyst viewer"`
	ClearanceLevel int    `json:"clearance_level" binding:"min=0,max=5"`
	Department     string `json:"department"`
}

// UpdateUserRequest is the body for PATCH /users/:id.
type UpdateUserRequest struct {
	FirstName      *string `json:"first_name"`
	LastName       *string `json:"last_name"`
	Role           *string `json:"role" binding:"omitempty,oneof=admin analyst viewer"`
	ClearanceLevel *int    `json:"clearance_level" binding:"omitempty,min=0,max=5"`
	Department     *string `json:"department"`
}

// ListUsersFilter holds query filters for listing users.
type ListUsersFilter struct {
	Status string
	Role   string
	Search string
	Page   int
	Limit  int
}

// PaginationMeta holds pagination metadata.
type PaginationMeta struct {
	Total  int `json:"total"`
	Page   int `json:"page"`
	Limit  int `json:"limit"`
	Pages  int `json:"pages"`
}
