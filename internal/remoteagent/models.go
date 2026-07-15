package remoteagent

import "time"

type RemoteAgent struct {
	ID            string     `json:"id" db:"id"`
	Name          string     `json:"name" db:"name"`
	Status        string     `json:"status" db:"status"` // online, offline, degraded
	Version       string     `json:"version" db:"version"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty" db:"last_heartbeat"`
	PublicKey     string     `json:"public_key" db:"public_key"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
}

type AgentCommand struct {
	ID        string    `json:"id" db:"id"`
	AgentID   string    `json:"agent_id" db:"agent_id"`
	Command   string    `json:"command" db:"command"` // restart, update, collect, stop
	Status    string    `json:"status" db:"status"`   // pending, executed, failed
	IssuedBy  string    `json:"issued_by" db:"issued_by"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type CreateCommandRequest struct {
	Command string `json:"command" binding:"required,oneof=restart update collect stop"`
}
