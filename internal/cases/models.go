package cases

import "time"

type Case struct {
	ID             string    `json:"id" db:"id"`
	Title          string    `json:"title" db:"title"`
	Description    string    `json:"description" db:"description"`
	Status         string    `json:"status" db:"status"`
	Priority       string    `json:"priority" db:"priority"`
	Classification string    `json:"classification" db:"classification"`
	OwnerID        string    `json:"owner_id" db:"owner_id"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
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
