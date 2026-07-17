package entities

import "time"

type Entity struct {
	ID             string                 `json:"id" bson:"_id"`
	Type           string                 `json:"type" bson:"type"`
	Properties     map[string]interface{} `json:"properties" bson:"properties"`
	Classification string                 `json:"classification" bson:"classification"`
	SourceID       string                 `json:"source_id" bson:"source_id"`
	CreatedAt      time.Time              `json:"created_at" bson:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at" bson:"updated_at"`
}

type Relationship struct {
	ID           string                 `json:"id" bson:"_id"`
	EntityIDFrom string                 `json:"entity_id_from" bson:"entity_id_from"`
	EntityIDTo   string                 `json:"entity_id_to" bson:"entity_id_to"`
	Type         string                 `json:"type" bson:"type"`
	Properties   map[string]interface{} `json:"properties" bson:"properties"`
	CreatedAt    time.Time              `json:"created_at" bson:"created_at"`
}

type CreateEntityRequest struct {
	Type           string                 `json:"type" binding:"required"`
	Properties     map[string]interface{} `json:"properties"`
	Classification string                 `json:"classification" binding:"required"`
	SourceID       string                 `json:"source_id"`
}

// UpdateEntityRequest is the body for PUT /entities/:id — a partial update.
// All fields are optional; only supplied fields are changed. Label is a
// convenience field that maps to properties["label"] when Properties itself
// is not also supplied (Properties, when present, replaces the whole map).
type UpdateEntityRequest struct {
	Type           *string                `json:"type"`
	Label          *string                `json:"label"`
	Properties     map[string]interface{} `json:"properties"`
	Classification *string                `json:"classification"`
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
