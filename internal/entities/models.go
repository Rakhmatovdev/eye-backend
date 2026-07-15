package entities

import "time"

type Entity struct {
	ID             string                 `json:"id" db:"id"`
	Type           string                 `json:"type" db:"type"`
	Properties     map[string]interface{} `json:"properties" db:"properties"`
	Classification string                 `json:"classification" db:"classification"`
	SourceID       string                 `json:"source_id" db:"source_id"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at" db:"updated_at"`
}

type Relationship struct {
	ID           string                 `json:"id" db:"id"`
	EntityIDFrom string                 `json:"entity_id_from" db:"entity_id_from"`
	EntityIDTo   string                 `json:"entity_id_to" db:"entity_id_to"`
	Type         string                 `json:"type" db:"type"`
	Properties   map[string]interface{} `json:"properties" db:"properties"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
}

type CreateEntityRequest struct {
	Type           string                 `json:"type" binding:"required"`
	Properties     map[string]interface{} `json:"properties"`
	Classification string                 `json:"classification" binding:"required"`
	SourceID       string                 `json:"source_id"`
}

type CreateRelationshipRequest struct {
	EntityIDFrom string                 `json:"entity_id_from" binding:"required"`
	EntityIDTo   string                 `json:"entity_id_to" binding:"required"`
	Type         string                 `json:"type" binding:"required"`
	Properties   map[string]interface{} `json:"properties"`
}

type ExpandRequest struct {
	NodeID string `json:"node_id" binding:"required"`
}

type PathRequest struct {
	StartID string `json:"start_id" binding:"required"`
	EndID   string `json:"end_id" binding:"required"`
}
