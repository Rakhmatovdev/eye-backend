package entities

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

func (s *Service) CreateEntity(ctx context.Context, req CreateEntityRequest) (*Entity, error) {
	id := uuid.New().String()
	propsJSON, _ := json.Marshal(req.Properties)

	e := &Entity{}
	var propsRaw []byte
	err := s.db.QueryRow(ctx,
		`INSERT INTO entities (id, type, properties, classification, source_id)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, type, properties, classification, source_id, created_at, updated_at`,
		id, req.Type, propsJSON, req.Classification, req.SourceID,
	).Scan(&e.ID, &e.Type, &propsRaw, &e.Classification, &e.SourceID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(propsRaw, &e.Properties)
	return e, nil
}

func (s *Service) GetEntity(ctx context.Context, id string) (*Entity, error) {
	e := &Entity{}
	var propsRaw []byte
	err := s.db.QueryRow(ctx,
		`SELECT id, type, properties, classification, source_id, created_at, updated_at
		 FROM entities WHERE id = $1`, id,
	).Scan(&e.ID, &e.Type, &propsRaw, &e.Classification, &e.SourceID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(propsRaw, &e.Properties)
	return e, nil
}

func (s *Service) ListEntities(ctx context.Context, search, entType string) ([]*Entity, error) {
	query := `SELECT id, type, properties, classification, source_id, created_at, updated_at 
	          FROM entities 
	          WHERE ($1 = '' OR type = $1)
	            AND ($2 = '' OR properties::text ILIKE $2)`
	
	searchVal := ""
	if search != "" {
		searchVal = "%" + search + "%"
	}

	rows, err := s.db.Query(ctx, query, entType, searchVal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*Entity
	for rows.Next() {
		e := &Entity{}
		var propsRaw []byte
		err = rows.Scan(&e.ID, &e.Type, &propsRaw, &e.Classification, &e.SourceID, &e.CreatedAt, &e.UpdatedAt)
		if err != nil {
			return nil, err
		}
		_ = json.Unmarshal(propsRaw, &e.Properties)
		list = append(list, e)
	}
	return list, nil
}

func (s *Service) CreateRelationship(ctx context.Context, req CreateRelationshipRequest) (*Relationship, error) {
	id := uuid.New().String()
	propsJSON, _ := json.Marshal(req.Properties)

	r := &Relationship{}
	var propsRaw []byte
	err := s.db.QueryRow(ctx,
		`INSERT INTO relationships (id, entity_id_from, entity_id_to, type, properties)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, entity_id_from, entity_id_to, type, properties, created_at`,
		id, req.EntityIDFrom, req.EntityIDTo, req.Type, propsJSON,
	).Scan(&r.ID, &r.EntityIDFrom, &r.EntityIDTo, &r.Type, &propsRaw, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(propsRaw, &r.Properties)
	return r, nil
}

func (s *Service) Expand(ctx context.Context, nodeID string) ([]*Entity, []*Relationship, error) {
	// Find all relationships connected to nodeID (either from or to)
	rows, err := s.db.Query(ctx,
		`SELECT id, entity_id_from, entity_id_to, type, properties, created_at 
		 FROM relationships 
		 WHERE entity_id_from = $1 OR entity_id_to = $1`, nodeID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var rels []*Relationship
	nodeIDs := make(map[string]bool)
	nodeIDs[nodeID] = true

	for rows.Next() {
		r := &Relationship{}
		var propsRaw []byte
		err = rows.Scan(&r.ID, &r.EntityIDFrom, &r.EntityIDTo, &r.Type, &propsRaw, &r.CreatedAt)
		if err != nil {
			return nil, nil, err
		}
		_ = json.Unmarshal(propsRaw, &r.Properties)
		rels = append(rels, r)
		nodeIDs[r.EntityIDFrom] = true
		nodeIDs[r.EntityIDTo] = true
	}

	// Fetch all connected entities
	var entities []*Entity
	if len(nodeIDs) > 0 {
		ids := []string{}
		for id := range nodeIDs {
			ids = append(ids, id)
		}

		rowsEnt, err := s.db.Query(ctx,
			`SELECT id, type, properties, classification, source_id, created_at, updated_at 
			 FROM entities WHERE id = ANY($1)`, ids)
		if err != nil {
			return nil, nil, err
		}
		defer rowsEnt.Close()

		for rowsEnt.Next() {
			e := &Entity{}
			var propsRaw []byte
			err = rowsEnt.Scan(&e.ID, &e.Type, &propsRaw, &e.Classification, &e.SourceID, &e.CreatedAt, &e.UpdatedAt)
			if err != nil {
				return nil, nil, err
			}
			_ = json.Unmarshal(propsRaw, &e.Properties)
			entities = append(entities, e)
		}
	}

	return entities, rels, nil
}

func (s *Service) FindPath(ctx context.Context, startID, endID string) ([]*Entity, []*Relationship, error) {
	// Simple BFS/recursive CTE to find path in Postgres
	query := `
		WITH RECURSIVE search_graph(from_id, to_id, depth, path) AS (
			SELECT entity_id_from, entity_id_to, 1, ARRAY[entity_id_from, entity_id_to]
			FROM relationships
			WHERE entity_id_from = $1 OR entity_id_to = $1
			UNION ALL
			SELECT r.entity_id_from, r.entity_id_to, sg.depth + 1, path || 
			       CASE WHEN sg.to_id = r.entity_id_from THEN r.entity_id_to ELSE r.entity_id_from END
			FROM relationships r
			JOIN search_graph sg ON sg.to_id = r.entity_id_from OR sg.from_id = r.entity_id_to
			WHERE depth < 5 AND NOT (
				CASE WHEN sg.to_id = r.entity_id_from THEN r.entity_id_to ELSE r.entity_id_from END = ANY(path)
			)
		)
		SELECT path FROM search_graph 
		WHERE path[array_length(path, 1)] = $2 
		ORDER BY depth ASC LIMIT 1
	`
	var path []string
	err := s.db.QueryRow(ctx, query, startID, endID).Scan(&path)
	if err == pgx.ErrNoRows {
		return []*Entity{}, []*Relationship{}, nil
	} else if err != nil {
		return nil, nil, err
	}

	// Fetch entities on path
	rowsEnt, err := s.db.Query(ctx,
		`SELECT id, type, properties, classification, source_id, created_at, updated_at 
		 FROM entities WHERE id = ANY($1)`, path)
	if err != nil {
		return nil, nil, err
	}
	defer rowsEnt.Close()

	var entities []*Entity
	for rowsEnt.Next() {
		e := &Entity{}
		var propsRaw []byte
		err = rowsEnt.Scan(&e.ID, &e.Type, &propsRaw, &e.Classification, &e.SourceID, &e.CreatedAt, &e.UpdatedAt)
		if err != nil {
			return nil, nil, err
		}
		_ = json.Unmarshal(propsRaw, &e.Properties)
		entities = append(entities, e)
	}

	// Fetch relationships between path nodes
	rowsRel, err := s.db.Query(ctx,
		`SELECT id, entity_id_from, entity_id_to, type, properties, created_at 
		 FROM relationships 
		 WHERE entity_id_from = ANY($1) AND entity_id_to = ANY($1)`, path)
	if err != nil {
		return nil, nil, err
	}
	defer rowsRel.Close()

	var rels []*Relationship
	for rowsRel.Next() {
		r := &Relationship{}
		var propsRaw []byte
		err = rowsRel.Scan(&r.ID, &r.EntityIDFrom, &r.EntityIDTo, &r.Type, &propsRaw, &r.CreatedAt)
		if err != nil {
			return nil, nil, err
		}
		_ = json.Unmarshal(propsRaw, &r.Properties)
		rels = append(rels, r)
	}

	return entities, rels, nil
}
