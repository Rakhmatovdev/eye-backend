package cases

import (
	"context"

	"intelligence-platform/internal/entities"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type Service struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

func NewService(db *pgxpool.Pool, log *zap.Logger) *Service {
	return &Service{db: db, log: log}
}

func (s *Service) Create(ctx context.Context, ownerID string, req CreateCaseRequest) (*Case, error) {
	id := uuid.New().String()
	c := &Case{}
	err := s.db.QueryRow(ctx,
		`INSERT INTO cases (id, title, description, status, priority, classification, owner_id)
		 VALUES ($1, $2, $3, 'open', $4, $5, $6)
		 RETURNING id, title, description, status, priority, classification, owner_id, created_at, updated_at`,
		id, req.Title, req.Description, req.Priority, req.Classification, ownerID,
	).Scan(&c.ID, &c.Title, &c.Description, &c.Status, &c.Priority, &c.Classification, &c.OwnerID, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func (s *Service) List(ctx context.Context, ownerID string) ([]*Case, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, title, description, status, priority, classification, owner_id, created_at, updated_at 
		 FROM cases ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*Case
	for rows.Next() {
		c := &Case{}
		err = rows.Scan(&c.ID, &c.Title, &c.Description, &c.Status, &c.Priority, &c.Classification, &c.OwnerID, &c.CreatedAt, &c.UpdatedAt)
		if err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, nil
}

func (s *Service) Get(ctx context.Context, id string) (*Case, error) {
	c := &Case{}
	err := s.db.QueryRow(ctx,
		`SELECT id, title, description, status, priority, classification, owner_id, created_at, updated_at 
		 FROM cases WHERE id = $1`, id,
	).Scan(&c.ID, &c.Title, &c.Description, &c.Status, &c.Priority, &c.Classification, &c.OwnerID, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func (s *Service) AddEntity(ctx context.Context, caseID, entityID, userID string) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO case_entities (case_id, entity_id, added_by)
		 VALUES ($1, $2, $3)
		 ON CONFLICT DO NOTHING`,
		caseID, entityID, userID,
	)
	return err
}

func (s *Service) GetEntities(ctx context.Context, caseID string) ([]*entities.Entity, error) {
	rows, err := s.db.Query(ctx,
		`SELECT e.id, e.type, e.properties, e.classification, e.source_id, e.created_at, e.updated_at
		 FROM entities e
		 JOIN case_entities ce ON ce.entity_id = e.id
		 WHERE ce.case_id = $1`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*entities.Entity
	for rows.Next() {
		e := &entities.Entity{}
		err = rows.Scan(&e.ID, &e.Type, &e.Properties, &e.Classification, &e.SourceID, &e.CreatedAt, &e.UpdatedAt)
		if err != nil {
			return nil, err
		}
		list = append(list, e)
	}
	return list, nil
}
