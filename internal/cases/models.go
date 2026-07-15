package cases

import "time"

type Case struct {
	ID             string    `json:"id" bson:"_id"`
	Title          string    `json:"title" bson:"title"`
	Description    string    `json:"description" bson:"description"`
	Status         string    `json:"status" bson:"status"`
	Priority       string    `json:"priority" bson:"priority"`
	Classification string    `json:"classification" bson:"classification"`
	OwnerID        string    `json:"owner_id" bson:"owner_id"`
	CreatedAt      time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" bson:"updated_at"`
}

type CreateCaseRequest struct {
	Title          string `json:"title" binding:"required"`
	Description    string `json:"description"`
	Priority       string `json:"priority" binding:"required,oneof=low medium high critical"`
	Classification string `json:"classification" binding:"required,oneof=public internal confidential secret"`
}

type AddEntityRequest struct {
	EntityID string `json:"entity_id" binding:"required"`
}
