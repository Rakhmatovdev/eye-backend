package security

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type Service struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

func NewService(db *pgxpool.Pool, log *zap.Logger) *Service {
	return &Service{db: db, log: log}
}

func (s *Service) GetDashboardStats(ctx context.Context) (map[string]interface{}, error) {
	var criticalOpen, highOpen, totalOpen, blockedCount int
	var openVulns, criticalVulns int

	_ = s.db.QueryRow(ctx, "SELECT COUNT(*) FROM security_incidents WHERE severity = 'critical' AND status != 'resolved'").Scan(&criticalOpen)
	_ = s.db.QueryRow(ctx, "SELECT COUNT(*) FROM security_incidents WHERE severity = 'high' AND status != 'resolved'").Scan(&highOpen)
	_ = s.db.QueryRow(ctx, "SELECT COUNT(*) FROM security_incidents WHERE status != 'resolved'").Scan(&totalOpen)
	_ = s.db.QueryRow(ctx, "SELECT COUNT(*) FROM blocklist").Scan(&blockedCount)
	_ = s.db.QueryRow(ctx, "SELECT COUNT(*) FROM vulnerabilities WHERE status IN ('open','patching')").Scan(&openVulns)
	_ = s.db.QueryRow(ctx, "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'critical' AND status NOT IN ('resolved')").Scan(&criticalVulns)

	riskScore := 12 + criticalOpen*16 + highOpen*7 + openVulns*3 + criticalVulns*6
	if riskScore > 100 {
		riskScore = 100
	}

	return map[string]interface{}{
		"critical_incidents":  criticalOpen,
		"high_incidents":      highOpen,
		"open_threats":        totalOpen,
		"blocked_items":       blockedCount,
		"open_vulnerabilities": openVulns,
		"overall_risk_score":  riskScore,
	}, nil
}

func (s *Service) ListIncidents(ctx context.Context) ([]*SecurityIncident, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, type, severity, risk_score, status, details, title, description, source_ip, affected_assets, tlp, assignee, ts
		 FROM security_incidents ORDER BY ts DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*SecurityIncident
	for rows.Next() {
		si, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, si)
	}
	return list, nil
}

func (s *Service) GetIncident(ctx context.Context, id string) (*SecurityIncident, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, type, severity, risk_score, status, details, title, description, source_ip, affected_assets, tlp, assignee, ts
		 FROM security_incidents WHERE id = $1`, id)
	return scanIncident(row)
}

// rowScanner abstracts pgx.Row / pgx.Rows so a single scan helper can serve both.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanIncident(row rowScanner) (*SecurityIncident, error) {
	si := &SecurityIncident{}
	var detailsRaw, assetsRaw []byte
	err := row.Scan(
		&si.ID, &si.Type, &si.Severity, &si.RiskScore, &si.Status, &detailsRaw,
		&si.Title, &si.Description, &si.SourceIP, &assetsRaw, &si.TLP, &si.Assignee, &si.Timestamp,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(detailsRaw, &si.Details)
	_ = json.Unmarshal(assetsRaw, &si.AffectedAssets)
	if si.AffectedAssets == nil {
		si.AffectedAssets = []string{}
	}
	return si, nil
}

func (s *Service) UpdateIncidentStatus(ctx context.Context, id, status string) error {
	_, err := s.db.Exec(ctx, "UPDATE security_incidents SET status = $1 WHERE id = $2", status, id)
	return err
}

func (s *Service) ResolveIncident(ctx context.Context, id string) error {
	return s.UpdateIncidentStatus(ctx, id, "resolved")
}

func (s *Service) AssignIncident(ctx context.Context, id, assignee string) error {
	_, err := s.db.Exec(ctx, "UPDATE security_incidents SET assignee = $1 WHERE id = $2", assignee, id)
	return err
}

func (s *Service) AddToBlocklist(ctx context.Context, req CreateBlocklistRequest, addedBy string) (*BlocklistItem, error) {
	id := uuid.New().String()
	item := &BlocklistItem{}
	if addedBy == "" {
		addedBy = "Admin"
	}
	err := s.db.QueryRow(ctx,
		`INSERT INTO blocklist (id, value, type, reason, added_by)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, value, type, reason, hit_count, added_by, expires_at, created_at`,
		id, req.Value, req.Type, req.Reason, addedBy,
	).Scan(&item.ID, &item.Value, &item.Type, &item.Reason, &item.HitCount, &item.AddedBy, &item.ExpiresAt, &item.CreatedAt)
	return item, err
}

func (s *Service) ListBlocklist(ctx context.Context) ([]*BlocklistItem, error) {
	rows, err := s.db.Query(ctx,
		"SELECT id, value, type, reason, hit_count, added_by, expires_at, created_at FROM blocklist ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*BlocklistItem
	for rows.Next() {
		b := &BlocklistItem{}
		err = rows.Scan(&b.ID, &b.Value, &b.Type, &b.Reason, &b.HitCount, &b.AddedBy, &b.ExpiresAt, &b.CreatedAt)
		if err != nil {
			return nil, err
		}
		list = append(list, b)
	}
	return list, nil
}

func (s *Service) RemoveFromBlocklist(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, "DELETE FROM blocklist WHERE id = $1", id)
	return err
}

func (s *Service) ListVulnerabilities(ctx context.Context) ([]*Vulnerability, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, cve_id, title, severity, cvss_score, status, affected_asset, component, description, remediation, discovered_at
		 FROM vulnerabilities ORDER BY cvss_score DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*Vulnerability
	for rows.Next() {
		v := &Vulnerability{}
		if err := rows.Scan(&v.ID, &v.CVEID, &v.Title, &v.Severity, &v.CVSSScore, &v.Status, &v.AffectedAsset, &v.Component, &v.Description, &v.Remediation, &v.DiscoveredAt); err != nil {
			return nil, err
		}
		list = append(list, v)
	}
	return list, nil
}

func (s *Service) UpdateVulnerabilityStatus(ctx context.Context, id, status string) (*Vulnerability, error) {
	_, err := s.db.Exec(ctx, "UPDATE vulnerabilities SET status = $1, updated_at = NOW() WHERE id = $2", status, id)
	if err != nil {
		return nil, err
	}
	v := &Vulnerability{}
	err = s.db.QueryRow(ctx,
		`SELECT id, cve_id, title, severity, cvss_score, status, affected_asset, component, description, remediation, discovered_at
		 FROM vulnerabilities WHERE id = $1`, id,
	).Scan(&v.ID, &v.CVEID, &v.Title, &v.Severity, &v.CVSSScore, &v.Status, &v.AffectedAsset, &v.Component, &v.Description, &v.Remediation, &v.DiscoveredAt)
	return v, err
}

func (s *Service) GetAttackMap(ctx context.Context) ([]*AttackMapNode, error) {
	rows, err := s.db.Query(ctx, `
		SELECT source_ip,
		       COUNT(*) AS cnt,
		       (ARRAY_AGG(severity ORDER BY
		           CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC
		       ))[1] AS top_severity
		FROM security_incidents
		WHERE source_ip IS NOT NULL AND source_ip != 'unknown' AND source_ip != ''
		GROUP BY source_ip
		ORDER BY cnt DESC
		LIMIT 9
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*AttackMapNode
	for rows.Next() {
		var ip, topSeverity string
		var count int
		if err := rows.Scan(&ip, &count, &topSeverity); err != nil {
			return nil, err
		}
		kind := "ip"
		if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.16.") {
			kind = "asset"
		}
		nodes = append(nodes, &AttackMapNode{
			ID:            ip,
			Label:         ip,
			Kind:          kind,
			IncidentCount: count,
			Severity:      topSeverity,
		})
	}
	return nodes, nil
}
