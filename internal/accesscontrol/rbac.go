package accesscontrol

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// Role represents a system role.
type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
}

// Permission represents a granular system permission.
type Permission struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Name     string `json:"name"`
}

// CreateRoleRequest is the body for POST /roles.
type CreateRoleRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

// AssignPermissionsRequest is the body for POST /roles/:id/permissions.
type AssignPermissionsRequest struct {
	PermissionIDs []string `json:"permission_ids" binding:"required"`
}

// RBACService handles role-based access control.
type RBACService struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

// NewRBACService creates a new RBAC service.
func NewRBACService(db *pgxpool.Pool, log *zap.Logger) *RBACService {
	return &RBACService{db: db, log: log}
}

// HasPermission checks if a user (by role) has a given permission.
func (s *RBACService) HasPermission(ctx context.Context, userID, resource, action string) (bool, error) {
	var count int
	err := s.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM user_roles ur
		JOIN role_permissions rp ON rp.role_id = ur.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE ur.user_id = $1 AND p.resource = $2 AND p.action = $3`,
		userID, resource, action).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ListRoles returns all roles with their permissions.
func (s *RBACService) ListRoles(ctx context.Context) ([]*Role, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, name, description, created_at FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []*Role
	for rows.Next() {
		r := &Role{}
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt); err != nil {
			return nil, err
		}
		perms, _ := s.getPermissionsForRole(ctx, r.ID)
		r.Permissions = perms
		roles = append(roles, r)
	}
	return roles, nil
}

// CreateRole creates a new role.
func (s *RBACService) CreateRole(ctx context.Context, req CreateRoleRequest) (*Role, error) {
	r := &Role{}
	err := s.db.QueryRow(ctx,
		`INSERT INTO roles (id, name, description) VALUES ($1,$2,$3)
		 RETURNING id, name, description, created_at`,
		uuid.New().String(), req.Name, req.Description,
	).Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create role failed: %w", err)
	}
	return r, nil
}

// ListPermissions returns all available permissions.
func (s *RBACService) ListPermissions(ctx context.Context) ([]*Permission, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, resource, action, name FROM permissions ORDER BY resource, action`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []*Permission
	for rows.Next() {
		p := &Permission{}
		if err := rows.Scan(&p.ID, &p.Resource, &p.Action, &p.Name); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, nil
}

// AssignPermissions replaces the permission set for a role.
func (s *RBACService) AssignPermissions(ctx context.Context, roleID string, req AssignPermissionsRequest) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Clear existing
	if _, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, roleID); err != nil {
		return err
	}

	// Insert new
	for _, permID := range req.PermissionIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
			roleID, permID); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (s *RBACService) getPermissionsForRole(ctx context.Context, roleID string) ([]Permission, error) {
	rows, err := s.db.Query(ctx,
		`SELECT p.id, p.resource, p.action, p.name FROM permissions p
		 JOIN role_permissions rp ON rp.permission_id = p.id
		 WHERE rp.role_id = $1`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []Permission
	for rows.Next() {
		p := Permission{}
		if err := rows.Scan(&p.ID, &p.Resource, &p.Action, &p.Name); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, nil
}
