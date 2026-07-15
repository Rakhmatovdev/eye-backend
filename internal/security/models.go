package security

import "time"

type SecurityIncident struct {
	ID              string                 `json:"id" db:"id"`
	Type            string                 `json:"type" db:"type"`
	Severity        string                 `json:"severity" db:"severity"`
	RiskScore       int                    `json:"risk_score" db:"risk_score"`
	Status          string                 `json:"status" db:"status"`
	Details         map[string]interface{} `json:"details" db:"details"`
	Title           string                 `json:"title" db:"title"`
	Description     string                 `json:"description" db:"description"`
	SourceIP        string                 `json:"source_ip" db:"source_ip"`
	AffectedAssets  []string               `json:"affected_assets" db:"affected_assets"`
	TLP             string                 `json:"tlp" db:"tlp"`
	Assignee        *string                `json:"assignee,omitempty" db:"assignee"`
	Timestamp       time.Time              `json:"timestamp" db:"ts"`
}

type ResolveIncidentRequest struct {
	Status string `json:"status" binding:"required,oneof=open investigating contained resolved"`
}

type AssignIncidentRequest struct {
	Assignee string `json:"assignee" binding:"required"`
}

type BlocklistItem struct {
	ID        string     `json:"id" db:"id"`
	Value     string     `json:"value" db:"value"`
	Type      string     `json:"type" db:"type"` // ip, domain, cidr, asn
	Reason    string     `json:"reason" db:"reason"`
	HitCount  int        `json:"hit_count" db:"hit_count"`
	AddedBy   string     `json:"added_by" db:"added_by"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}

type CreateBlocklistRequest struct {
	Value  string `json:"value" binding:"required"`
	Type   string `json:"type" binding:"required,oneof=ip domain cidr asn"`
	Reason string `json:"reason"`
}

type Vulnerability struct {
	ID            string    `json:"id" db:"id"`
	CVEID         *string   `json:"cve_id,omitempty" db:"cve_id"`
	Title         string    `json:"title" db:"title"`
	Severity      string    `json:"severity" db:"severity"`
	CVSSScore     float64   `json:"cvss_score" db:"cvss_score"`
	Status        string    `json:"status" db:"status"`
	AffectedAsset string    `json:"affected_asset" db:"affected_asset"`
	Component     string    `json:"component" db:"component"`
	Description   string    `json:"description" db:"description"`
	Remediation   string    `json:"remediation" db:"remediation"`
	DiscoveredAt  time.Time `json:"discovered_at" db:"discovered_at"`
}

type UpdateVulnerabilityStatusRequest struct {
	Status string `json:"status" binding:"required,oneof=open patching mitigated resolved accepted_risk"`
}

type AttackMapNode struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	Kind          string `json:"kind"` // ip, asset
	IncidentCount int    `json:"incident_count"`
	Severity      string `json:"severity"`
}
