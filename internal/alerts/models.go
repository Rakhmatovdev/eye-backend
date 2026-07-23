// Package alerts implements the watchlist + alert-rule engine: analysts flag
// entities of interest on a watchlist, admins configure alert rules, and a
// background evaluator (evaluator.go) periodically matches live platform data
// (sensor detections, military threat tracks, entity risk scores) against
// those rules, inserting deduped alerts and pushing new ones over the
// existing WS hub. All data here is synthetic demo data.
package alerts

import (
	stderrors "errors"
	"time"
)

// ErrAlreadyWatchlisted is returned by AddWatchlist when the entity is
// already present on the watchlist (dedupe on entity_id).
var ErrAlreadyWatchlisted = stderrors.New("entity already on watchlist")

// ErrEntityNotFound is returned by AddWatchlist when the referenced entity
// does not exist.
var ErrEntityNotFound = stderrors.New("entity not found")

// WatchlistEntry is a single entity flagged for heightened monitoring.
type WatchlistEntry struct {
	ID          string    `json:"id" bson:"_id"`
	EntityID    string    `json:"entity_id" bson:"entity_id"`
	EntityLabel string    `json:"entity_label" bson:"entity_label"`
	Note        string    `json:"note" bson:"note"`
	CreatedBy   string    `json:"created_by" bson:"created_by"`
	CreatedAt   time.Time `json:"created_at" bson:"created_at"`
}

// AddWatchlistRequest is the payload for POST /watchlist.
type AddWatchlistRequest struct {
	EntityID string `json:"entity_id" binding:"required"`
	Note     string `json:"note"`
}

// AlertRule configures one detection rule the background evaluator checks on
// every tick. Type is one of watchlist_detection | threat_class | risk_threshold.
// Params is rule-type-specific:
//   - threat_class:   {"classes": ["hostile", ...]}
//   - risk_threshold: {"min_score": 80}
//   - watchlist_detection: unused (rule needs no extra params)
type AlertRule struct {
	ID        string                 `json:"id" bson:"_id"`
	Name      string                 `json:"name" bson:"name"`
	Type      string                 `json:"type" bson:"type"`
	Enabled   bool                   `json:"enabled" bson:"enabled"`
	Severity  string                 `json:"severity" bson:"severity"`
	Params    map[string]interface{} `json:"params" bson:"params"`
	CreatedAt time.Time              `json:"created_at" bson:"created_at"`
}

// RuleRequest is the payload for POST/PUT /alerts/rules.
type RuleRequest struct {
	Name     string                 `json:"name" binding:"required"`
	Type     string                 `json:"type" binding:"required,oneof=watchlist_detection threat_class risk_threshold"`
	Enabled  *bool                  `json:"enabled"`
	Severity string                 `json:"severity" binding:"required,oneof=critical high medium low"`
	Params   map[string]interface{} `json:"params"`
}

// Alert is a single generated alert instance — a rule matched a subject
// (an entity, threat track, or sensor detection) at a point in time.
type Alert struct {
	ID     string `json:"id" bson:"_id"`
	RuleID string `json:"rule_id" bson:"rule_id"`
	// RuleName/Severity are copied from the rule at generation time so an
	// alert's display doesn't change retroactively if the rule is edited later.
	RuleName string `json:"rule_name" bson:"rule_name"`
	Severity string `json:"severity" bson:"severity"`
	Title    string `json:"title" bson:"title"`
	Message  string `json:"message" bson:"message"`

	EntityID    string `json:"entity_id,omitempty" bson:"entity_id,omitempty"`
	ThreatID    string `json:"threat_id,omitempty" bson:"threat_id,omitempty"`
	DetectionID string `json:"detection_id,omitempty" bson:"detection_id,omitempty"`

	// SubjectKey is the dedupe key (rule_id + subject) — internal only, never
	// serialized to clients.
	SubjectKey string `json:"-" bson:"subject_key"`

	Acknowledged bool       `json:"acknowledged" bson:"acknowledged"`
	AckBy        string     `json:"ack_by,omitempty" bson:"ack_by,omitempty"`
	AckAt        *time.Time `json:"ack_at,omitempty" bson:"ack_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at" bson:"created_at"`
}
