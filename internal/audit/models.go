package audit

import "time"

type AuditLog struct {
	ID        int       `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	Action    string    `json:"action" db:"action"`
	Resource  string    `json:"resource" db:"resource"`
	IP        string    `json:"ip" db:"ip"`
	Result    string    `json:"result" db:"result"`
	Hash      string    `json:"hash" db:"hash"`
	PrevHash  string    `json:"prev_hash" db:"prev_hash"`
	Timestamp time.Time `json:"timestamp" db:"ts"`
}
