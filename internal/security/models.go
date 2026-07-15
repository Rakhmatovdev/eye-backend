package security

import "time"

type SecurityIncident struct {
	ID             string                 `json:"id" bson:"_id"`
	Type           string                 `json:"type" bson:"type"`
	Severity       string                 `json:"severity" bson:"severity"`
	RiskScore      int                    `json:"risk_score" bson:"risk_score"`
	Status         string                 `json:"status" bson:"status"`
	Details        map[string]interface{} `json:"details" bson:"details"`
	Title          string                 `json:"title" bson:"title"`
	Description    string                 `json:"description" bson:"description"`
	SourceIP       string                 `json:"source_ip" bson:"source_ip"`
	AffectedAssets []string               `json:"affected_assets" bson:"affected_assets"`
	TLP            string                 `json:"tlp" bson:"tlp"`
	Assignee       *string                `json:"assignee,omitempty" bson:"assignee"`
	Timestamp      time.Time              `json:"timestamp" bson:"ts"`
}

type ResolveIncidentRequest struct {
	Status string `json:"status" binding:"required,oneof=open investigating contained resolved"`
}

type AssignIncidentRequest struct {
	Assignee string `json:"assignee" binding:"required"`
}

type BlocklistItem struct {
	ID        string     `json:"id" bson:"_id"`
	Value     string     `json:"value" bson:"value"`
	Type      string     `json:"type" bson:"type"` // ip, domain, cidr, asn
	Reason    string     `json:"reason" bson:"reason"`
	HitCount  int        `json:"hit_count" bson:"hit_count"`
	AddedBy   string     `json:"added_by" bson:"added_by"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" bson:"expires_at"`
	CreatedAt time.Time  `json:"created_at" bson:"created_at"`
}

type CreateBlocklistRequest struct {
	Value  string `json:"value" binding:"required"`
	Type   string `json:"type" binding:"required,oneof=ip domain cidr asn"`
	Reason string `json:"reason"`
}

type Vulnerability struct {
	ID            string    `json:"id" bson:"_id"`
	CVEID         *string   `json:"cve_id,omitempty" bson:"cve_id"`
	Title         string    `json:"title" bson:"title"`
	Severity      string    `json:"severity" bson:"severity"`
	CVSSScore     float64   `json:"cvss_score" bson:"cvss_score"`
	Status        string    `json:"status" bson:"status"`
	AffectedAsset string    `json:"affected_asset" bson:"affected_asset"`
	Component     string    `json:"component" bson:"component"`
	Description   string    `json:"description" bson:"description"`
	Remediation   string    `json:"remediation" bson:"remediation"`
	DiscoveredAt  time.Time `json:"discovered_at" bson:"discovered_at"`
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
