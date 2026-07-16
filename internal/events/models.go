package events

import "time"

// Event is a time-stamped occurrence tied to an entity — the atoms of the
// timeline / "Time Analysis" view. Stored in the `events` collection.
type Event struct {
	ID          string    `json:"id" bson:"_id"`
	Timestamp   time.Time `json:"timestamp" bson:"timestamp"`
	EntityID    string    `json:"entity_id" bson:"entity_id"`
	Title       string    `json:"title" bson:"title"`
	Description string    `json:"description" bson:"description"`
	Type        string    `json:"type" bson:"type"`
	Location    string    `json:"location" bson:"location"`
	CreatedAt   time.Time `json:"created_at" bson:"created_at"`
}

// CreateEventRequest is the payload for POST /timeline.
type CreateEventRequest struct {
	Timestamp   time.Time `json:"timestamp" binding:"required"`
	EntityID    string    `json:"entity_id"`
	Title       string    `json:"title" binding:"required"`
	Description string    `json:"description"`
	Type        string    `json:"type"`
	Location    string    `json:"location"`
}
