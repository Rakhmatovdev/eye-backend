package users

import (
	"time"

	"intelligence-platform/pkg/pagination"
)

// User represents a platform user (full model).
type User struct {
	ID             string     `json:"id" bson:"_id"`
	Email          string     `json:"email" bson:"email"`
	FirstName      string     `json:"first_name" bson:"first_name"`
	LastName       string     `json:"last_name" bson:"last_name"`
	Role           string     `json:"role" bson:"role"`
	ClearanceLevel int        `json:"clearance_level" bson:"clearance_level"`
	Status         string     `json:"status" bson:"status"`
	Department     string     `json:"department" bson:"department"`
	LastLogin      *time.Time `json:"last_login,omitempty" bson:"last_login"`
	CreatedAt      time.Time  `json:"created_at" bson:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" bson:"updated_at"`
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

// ListUsersFilter holds query filters for listing users. Pg is nil when the
// caller sent neither ?page= nor ?limit=, meaning List returns every match
// (pre-pagination behaviour) instead of a single page.
type ListUsersFilter struct {
	Status string
	Role   string
	Search string
	Pg     *pagination.Params
}
