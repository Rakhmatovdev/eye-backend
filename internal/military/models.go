package military

import "time"

// Package military models a Common Operating Picture (COP) for the tactical
// command view. All data is synthetic demo data (Palantir-style simulation) —
// this is a situational-awareness visualization, not a real fires/targeting system.

// Unit is a friendly (own-force) unit or asset on the map.
type Unit struct {
	ID        string    `json:"id" bson:"_id"`
	Callsign  string    `json:"callsign" bson:"callsign"`
	Name      string    `json:"name" bson:"name"`
	Type      string    `json:"type" bson:"type"`   // infantry, armor, uav, air, recon, hq, logistics
	Domain    string    `json:"domain" bson:"domain"` // land, air, sea, cyber
	Status    string    `json:"status" bson:"status"` // active, standby, moving, engaged
	Readiness string    `json:"readiness" bson:"readiness"` // green, amber, red
	Lat       float64   `json:"lat" bson:"lat"`
	Lng       float64   `json:"lng" bson:"lng"`
	Strength  int       `json:"strength" bson:"strength"`
	Heading   int       `json:"heading" bson:"heading"` // degrees 0-359
	Speed     float64   `json:"speed" bson:"speed"`     // km/h
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

// Threat is a hostile / suspect / unknown contact (track) on the map.
type Threat struct {
	ID             string    `json:"id" bson:"_id"`
	Designation    string    `json:"designation" bson:"designation"`
	Type           string    `json:"type" bson:"type"`                     // armor, infantry, uav, aircraft, artillery, convoy, unknown
	Classification string    `json:"classification" bson:"classification"` // hostile, suspect, unknown
	ThreatLevel    string    `json:"threat_level" bson:"threat_level"`     // critical, high, medium, low
	Lat            float64   `json:"lat" bson:"lat"`
	Lng            float64   `json:"lng" bson:"lng"`
	Heading        int       `json:"heading" bson:"heading"`
	Speed          float64   `json:"speed" bson:"speed"`
	Confidence     float64   `json:"confidence" bson:"confidence"` // 0..1 track confidence
	EntityID       string    `json:"entity_id" bson:"entity_id"`   // optional link to an intel entity
	LastSeen       time.Time `json:"last_seen" bson:"last_seen"`
}

// Mission is an entry on the operations / mission board.
type Mission struct {
	ID            string    `json:"id" bson:"_id"`
	Name          string    `json:"name" bson:"name"`
	Status        string    `json:"status" bson:"status"`     // planning, active, on_hold, complete
	Priority      string    `json:"priority" bson:"priority"` // routine, priority, immediate, flash
	Objective     string    `json:"objective" bson:"objective"`
	Area          string    `json:"area" bson:"area"`
	AssignedUnits []string  `json:"assigned_units" bson:"assigned_units"`
	Progress      int       `json:"progress" bson:"progress"` // 0..100
	StartsAt      time.Time `json:"starts_at" bson:"starts_at"`
	UpdatedAt     time.Time `json:"updated_at" bson:"updated_at"`
}

// Stats summarises the COP for the command dashboard header.
type Stats struct {
	Units          int64 `json:"units"`
	UnitsReady     int64 `json:"units_ready"`
	Threats        int64 `json:"threats"`
	CriticalThreats int64 `json:"critical_threats"`
	ActiveMissions int64 `json:"active_missions"`
}
