package audit

import "time"

type AuditLog struct {
	ID        int64     `json:"id" bson:"id"`
	UserID    string    `json:"user_id" bson:"user_id"`
	Action    string    `json:"action" bson:"action"`
	Resource  string    `json:"resource" bson:"resource"`
	IP        string    `json:"ip" bson:"ip"`
	Result    string    `json:"result" bson:"result"`
	Hash      string    `json:"hash" bson:"hash"`
	PrevHash  string    `json:"prev_hash" bson:"prev_hash"`
	Timestamp time.Time `json:"timestamp" bson:"ts"`
}
