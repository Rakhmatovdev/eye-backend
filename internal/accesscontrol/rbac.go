package accesscontrol

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// Role represents a system role.
type Role struct {
	ID          string       `json:"id" bson:"_id"`
	Name        string       `json:"name" bson:"name"`
	Description string       `json:"description" bson:"description"`
	Permissions []Permission `json:"permissions,omitempty" bson:"-"`
	CreatedAt   time.Time    `json:"created_at" bson:"created_at"`
}

// Permission represents a granular system permission.
type Permission struct {
	ID       string `json:"id" bson:"_id"`
	Resource string `json:"resource" bson:"resource"`
	Action   string `json:"action" bson:"action"`
	Name     string `json:"name" bson:"name"`
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
	db  *mongo.Database
	log *zap.Logger
}

// NewRBACService creates a new RBAC service.
func NewRBACService(db *mongo.Database, log *zap.Logger) *RBACService {
	return &RBACService{db: db, log: log}
}

func (s *RBACService) roles() *mongo.Collection           { return s.db.Collection("roles") }
func (s *RBACService) permissions() *mongo.Collection     { return s.db.Collection("permissions") }
func (s *RBACService) rolePermissions() *mongo.Collection { return s.db.Collection("role_permissions") }
func (s *RBACService) userRoles() *mongo.Collection       { return s.db.Collection("user_roles") }

// HasPermission checks if a user (by their roles) has a given permission.
func (s *RBACService) HasPermission(ctx context.Context, userID, resource, action string) (bool, error) {
	// roles assigned to the user
	roleIDs, err := s.distinctStrings(ctx, s.userRoles(), "role_id", bson.M{"user_id": userID})
	if err != nil || len(roleIDs) == 0 {
		return false, err
	}

	// permissions granted to those roles
	permIDs, err := s.distinctStrings(ctx, s.rolePermissions(), "permission_id", bson.M{"role_id": bson.M{"$in": roleIDs}})
	if err != nil || len(permIDs) == 0 {
		return false, err
	}

	count, err := s.permissions().CountDocuments(ctx, bson.M{
		"_id":      bson.M{"$in": permIDs},
		"resource": resource,
		"action":   action,
	})
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ListRoles returns all roles with their permissions.
func (s *RBACService) ListRoles(ctx context.Context) ([]*Role, error) {
	cur, err := s.roles().Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "name", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var roles []*Role
	if err := cur.All(ctx, &roles); err != nil {
		return nil, err
	}
	for _, r := range roles {
		perms, _ := s.getPermissionsForRole(ctx, r.ID)
		r.Permissions = perms
	}
	return roles, nil
}

// CreateRole creates a new role.
func (s *RBACService) CreateRole(ctx context.Context, req CreateRoleRequest) (*Role, error) {
	r := &Role{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   time.Now(),
	}
	if _, err := s.roles().InsertOne(ctx, r); err != nil {
		return nil, fmt.Errorf("create role failed: %w", err)
	}
	return r, nil
}

// ListPermissions returns all available permissions.
func (s *RBACService) ListPermissions(ctx context.Context) ([]*Permission, error) {
	cur, err := s.permissions().Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "resource", Value: 1}, {Key: "action", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var perms []*Permission
	if err := cur.All(ctx, &perms); err != nil {
		return nil, err
	}
	return perms, nil
}

// AssignPermissions replaces the permission set for a role.
func (s *RBACService) AssignPermissions(ctx context.Context, roleID string, req AssignPermissionsRequest) error {
	if _, err := s.rolePermissions().DeleteMany(ctx, bson.M{"role_id": roleID}); err != nil {
		return err
	}
	if len(req.PermissionIDs) == 0 {
		return nil
	}
	docs := make([]interface{}, 0, len(req.PermissionIDs))
	for _, permID := range req.PermissionIDs {
		docs = append(docs, bson.M{"role_id": roleID, "permission_id": permID})
	}
	_, err := s.rolePermissions().InsertMany(ctx, docs)
	return err
}

func (s *RBACService) getPermissionsForRole(ctx context.Context, roleID string) ([]Permission, error) {
	permIDs, err := s.distinctStrings(ctx, s.rolePermissions(), "permission_id", bson.M{"role_id": roleID})
	if err != nil || len(permIDs) == 0 {
		return nil, err
	}
	cur, err := s.permissions().Find(ctx, bson.M{"_id": bson.M{"$in": permIDs}})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var perms []Permission
	if err := cur.All(ctx, &perms); err != nil {
		return nil, err
	}
	return perms, nil
}

// distinctStrings returns the distinct string values of a field matching a filter.
func (s *RBACService) distinctStrings(ctx context.Context, col *mongo.Collection, field string, filter bson.M) ([]string, error) {
	vals, err := col.Distinct(ctx, field, filter)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out, nil
}
