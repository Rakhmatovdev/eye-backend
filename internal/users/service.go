package users

import (
	"context"
	"fmt"
	"math"
	"strings"

	"intelligence-platform/pkg/crypto"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// Service handles user management business logic.
type Service struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

// NewService creates a new users service.
func NewService(db *pgxpool.Pool, log *zap.Logger) *Service {
	return &Service{db: db, log: log}
}

// List returns a paginated list of users with optional filters.
func (s *Service) List(ctx context.Context, f ListUsersFilter) ([]*User, PaginationMeta, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.Limit < 1 || f.Limit > 100 {
		f.Limit = 20
	}
	offset := (f.Page - 1) * f.Limit

	conditions := []string{}
	args := []interface{}{}
	argIdx := 1

	if f.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, f.Status)
		argIdx++
	}
	if f.Role != "" {
		conditions = append(conditions, fmt.Sprintf("role = $%d", argIdx))
		args = append(args, f.Role)
		argIdx++
	}
	if f.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(email ILIKE $%d OR first_name ILIKE $%d OR last_name ILIKE $%d)",
			argIdx, argIdx, argIdx))
		args = append(args, "%"+f.Search+"%")
		argIdx++
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users %s", where)
	var total int
	if err := s.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, PaginationMeta{}, fmt.Errorf("count query failed: %w", err)
	}

	// Fetch
	query := fmt.Sprintf(
		`SELECT id, email, first_name, last_name, role, clearance_level, status, department, last_login, created_at, updated_at
		 FROM users %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		where, argIdx, argIdx+1)
	args = append(args, f.Limit, offset)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, PaginationMeta{}, fmt.Errorf("list query failed: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.Email, &u.FirstName, &u.LastName, &u.Role,
			&u.ClearanceLevel, &u.Status, &u.Department, &u.LastLogin, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, PaginationMeta{}, err
		}
		users = append(users, u)
	}

	pages := int(math.Ceil(float64(total) / float64(f.Limit)))
	meta := PaginationMeta{Total: total, Page: f.Page, Limit: f.Limit, Pages: pages}
	return users, meta, nil
}

// Create creates a new user.
func (s *Service) Create(ctx context.Context, req CreateUserRequest) (*User, error) {
	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	id := uuid.New().String()
	dep := req.Department
	if dep == "" {
		dep = "General"
	}

	u := &User{}
	err = s.db.QueryRow(ctx,
		`INSERT INTO users (id, email, password_hash, first_name, last_name, role, clearance_level, status, department)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8)
		 RETURNING id, email, first_name, last_name, role, clearance_level, status, department, last_login, created_at, updated_at`,
		id, req.Email, hash, req.FirstName, req.LastName, req.Role, req.ClearanceLevel, dep,
	).Scan(&u.ID, &u.Email, &u.FirstName, &u.LastName, &u.Role, &u.ClearanceLevel,
		&u.Status, &u.Department, &u.LastLogin, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create user failed: %w", err)
	}
	return u, nil
}

// GetByID retrieves a user by ID.
func (s *Service) GetByID(ctx context.Context, id string) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(ctx,
		`SELECT id, email, first_name, last_name, role, clearance_level, status, department, last_login, created_at, updated_at
		 FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Email, &u.FirstName, &u.LastName, &u.Role, &u.ClearanceLevel,
		&u.Status, &u.Department, &u.LastLogin, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	return u, nil
}

// Update applies a partial update to a user.
func (s *Service) Update(ctx context.Context, id string, req UpdateUserRequest) (*User, error) {
	sets := []string{}
	args := []interface{}{}
	argIdx := 1

	if req.FirstName != nil {
		sets = append(sets, fmt.Sprintf("first_name = $%d", argIdx))
		args = append(args, *req.FirstName)
		argIdx++
	}
	if req.LastName != nil {
		sets = append(sets, fmt.Sprintf("last_name = $%d", argIdx))
		args = append(args, *req.LastName)
		argIdx++
	}
	if req.Role != nil {
		sets = append(sets, fmt.Sprintf("role = $%d", argIdx))
		args = append(args, *req.Role)
		argIdx++
	}
	if req.ClearanceLevel != nil {
		sets = append(sets, fmt.Sprintf("clearance_level = $%d", argIdx))
		args = append(args, *req.ClearanceLevel)
		argIdx++
	}
	if req.Department != nil {
		sets = append(sets, fmt.Sprintf("department = $%d", argIdx))
		args = append(args, *req.Department)
		argIdx++
	}
	if len(sets) == 0 {
		return s.GetByID(ctx, id)
	}

	sets = append(sets, "updated_at = NOW()")
	args = append(args, id)

	query := fmt.Sprintf(
		`UPDATE users SET %s WHERE id = $%d
		 RETURNING id, email, first_name, last_name, role, clearance_level, status, department, last_login, created_at, updated_at`,
		strings.Join(sets, ", "), argIdx)

	u := &User{}
	err := s.db.QueryRow(ctx, query, args...).
		Scan(&u.ID, &u.Email, &u.FirstName, &u.LastName, &u.Role, &u.ClearanceLevel,
			&u.Status, &u.Department, &u.LastLogin, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("update user failed: %w", err)
	}
	return u, nil
}

// Delete soft-deletes a user by setting status to 'deleted'.
func (s *Service) Delete(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `UPDATE users SET status='deleted', updated_at=NOW() WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// Suspend sets a user's status to 'suspended'.
func (s *Service) Suspend(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET status='suspended', updated_at=NOW() WHERE id=$1`, id)
	return err
}

// Activate sets a user's status to 'active'.
func (s *Service) Activate(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET status='active', updated_at=NOW() WHERE id=$1`, id)
	return err
}
