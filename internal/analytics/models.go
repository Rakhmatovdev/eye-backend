// Package analytics implements server-side, on-request AI pattern detection
// over live platform data (no cron, no ML — simple deterministic heuristics
// computed fresh on every GET /analytics/patterns call). All data is
// synthetic demo data.
package analytics

import "time"

// Pattern is one detected pattern instance.
type Pattern struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // co_location | hub_entity | threat_correlation | burst_activity
	Score       int       `json:"score"` // 0-100
	Title       string    `json:"title"`
	Description string    `json:"description"`
	EntityIDs   []string  `json:"entity_ids"`
	Evidence    []string  `json:"evidence"`
	DetectedAt  time.Time `json:"detected_at"`
}
