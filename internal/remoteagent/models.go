package remoteagent

import "time"

type RemoteAgent struct {
	ID            string     `json:"id" bson:"_id"`
	Name          string     `json:"name" bson:"name"`
	Status        string     `json:"status" bson:"status"` // online, offline, degraded
	Version       string     `json:"version" bson:"version"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty" bson:"last_heartbeat"`
	PublicKey     string     `json:"public_key" bson:"public_key"`
	CreatedAt     time.Time  `json:"created_at" bson:"created_at"`
}

type AgentCommand struct {
	ID        string    `json:"id" bson:"_id"`
	AgentID   string    `json:"agent_id" bson:"agent_id"`
	Command   string    `json:"command" bson:"command"` // restart, update, collect, stop
	Status    string    `json:"status" bson:"status"`   // pending, executed, failed
	IssuedBy  string    `json:"issued_by" bson:"issued_by"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

type CreateCommandRequest struct {
	Command string `json:"command" binding:"required,oneof=restart update collect stop"`
}
