package users

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"intelligence-platform/pkg/crypto"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// Service handles user management business logic.
type Service struct {
	db  *mongo.Database
	log *zap.Logger
}

// NewService creates a new users service.
func NewService(db *mongo.Database, log *zap.Logger) *Service {
	return &Service{db: db, log: log}
}

func (s *Service) col() *mongo.Collection { return s.db.Collection("users") }

// List returns users matching the optional filters. When f.Pg is nil, every
// match is returned (pre-pagination behaviour, total is 0 and should be
// ignored by the caller); otherwise a single page plus the total match count
// is returned.
func (s *Service) List(ctx context.Context, f ListUsersFilter) ([]*User, int64, error) {
	filter := bson.M{}
	if f.Status != "" {
		filter["status"] = f.Status
	}
	if f.Role != "" {
		filter["role"] = f.Role
	}
	if f.Search != "" {
		rx := primitive.Regex{Pattern: regexp.QuoteMeta(f.Search), Options: "i"}
		filter["$or"] = bson.A{
			bson.M{"email": rx},
			bson.M{"first_name": rx},
			bson.M{"last_name": rx},
		}
	}

	opts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetProjection(bson.M{"password_hash": 0})

	var total int64
	if f.Pg != nil {
		var err error
		total, err = s.col().CountDocuments(ctx, filter)
		if err != nil {
			return nil, 0, fmt.Errorf("count query failed: %w", err)
		}
		opts.SetSkip(f.Pg.Skip()).SetLimit(f.Pg.Take())
	}

	cur, err := s.col().Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("list query failed: %w", err)
	}
	defer cur.Close(ctx)

	users := []*User{}
	if err := cur.All(ctx, &users); err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

// Create creates a new user.
func (s *Service) Create(ctx context.Context, req CreateUserRequest) (*User, error) {
	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	dep := req.Department
	if dep == "" {
		dep = "General"
	}

	now := time.Now()
	u := &User{
		ID:             uuid.New().String(),
		Email:          req.Email,
		FirstName:      req.FirstName,
		LastName:       req.LastName,
		Role:           req.Role,
		ClearanceLevel: req.ClearanceLevel,
		Status:         "active",
		Department:     dep,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	doc := bson.M{
		"_id":             u.ID,
		"email":           u.Email,
		"password_hash":   hash,
		"first_name":      u.FirstName,
		"last_name":       u.LastName,
		"role":            u.Role,
		"clearance_level": u.ClearanceLevel,
		"status":          u.Status,
		"department":      u.Department,
		"last_login":      nil,
		"created_at":      u.CreatedAt,
		"updated_at":      u.UpdatedAt,
	}

	if _, err := s.col().InsertOne(ctx, doc); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return nil, fmt.Errorf("a user with this email already exists")
		}
		return nil, fmt.Errorf("create user failed: %w", err)
	}
	return u, nil
}

// GetByID retrieves a user by ID.
func (s *Service) GetByID(ctx context.Context, id string) (*User, error) {
	u := &User{}
	err := s.col().FindOne(ctx, bson.M{"_id": id}, options.FindOne().SetProjection(bson.M{"password_hash": 0})).Decode(u)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	return u, nil
}

// Update applies a partial update to a user.
func (s *Service) Update(ctx context.Context, id string, req UpdateUserRequest) (*User, error) {
	set := bson.M{}
	if req.FirstName != nil {
		set["first_name"] = *req.FirstName
	}
	if req.LastName != nil {
		set["last_name"] = *req.LastName
	}
	if req.Role != nil {
		set["role"] = *req.Role
	}
	if req.ClearanceLevel != nil {
		set["clearance_level"] = *req.ClearanceLevel
	}
	if req.Department != nil {
		set["department"] = *req.Department
	}
	if len(set) == 0 {
		return s.GetByID(ctx, id)
	}
	set["updated_at"] = time.Now()

	res, err := s.col().UpdateByID(ctx, id, bson.M{"$set": set})
	if err != nil {
		return nil, fmt.Errorf("update user failed: %w", err)
	}
	if res.MatchedCount == 0 {
		return nil, errors.New("user not found")
	}
	return s.GetByID(ctx, id)
}

// Delete soft-deletes a user by setting status to 'deleted'.
func (s *Service) Delete(ctx context.Context, id string) error {
	res, err := s.col().UpdateByID(ctx, id, bson.M{"$set": bson.M{"status": "deleted", "updated_at": time.Now()}})
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// Suspend sets a user's status to 'suspended'.
func (s *Service) Suspend(ctx context.Context, id string) error {
	_, err := s.col().UpdateByID(ctx, id, bson.M{"$set": bson.M{"status": "suspended", "updated_at": time.Now()}})
	return err
}

// Activate sets a user's status to 'active'.
func (s *Service) Activate(ctx context.Context, id string) error {
	_, err := s.col().UpdateByID(ctx, id, bson.M{"$set": bson.M{"status": "active", "updated_at": time.Now()}})
	return err
}
