// Package seed creates indexes and bootstraps demo/reference data on startup.
// It is idempotent: users are upserted, demo collections are only filled when
// empty. Replaces the old SQL migrations (001_init / 002_security_enhancements).
package seed

import (
	"context"
	"time"

	"intelligence-platform/pkg/crypto"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// Run ensures indexes and seed data exist.
func Run(ctx context.Context, db *mongo.Database, log *zap.Logger) error {
	if err := ensureIndexes(ctx, db); err != nil {
		log.Warn("failed to create some indexes", zap.Error(err))
	}
	if err := seedUsers(ctx, db, log); err != nil {
		return err
	}
	if err := seedIncidents(ctx, db, log); err != nil {
		return err
	}
	if err := seedVulnerabilities(ctx, db, log); err != nil {
		return err
	}
	if err := seedBlocklist(ctx, db, log); err != nil {
		return err
	}
	if err := seedRBAC(ctx, db, log); err != nil {
		return err
	}
	return nil
}

func ensureIndexes(ctx context.Context, db *mongo.Database) error {
	if _, err := db.Collection("users").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		return err
	}
	// TTL index: refresh tokens auto-expire at their expires_at instant.
	if _, err := db.Collection("refresh_tokens").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	}); err != nil {
		return err
	}
	if _, err := db.Collection("audit_logs").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "id", Value: -1}},
	}); err != nil {
		return err
	}
	if _, err := db.Collection("case_entities").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "case_id", Value: 1}, {Key: "entity_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		return err
	}
	if _, err := db.Collection("blocklist").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "value", Value: 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		return err
	}
	return nil
}

func seedUsers(ctx context.Context, db *mongo.Database, log *zap.Logger) error {
	adminHash, err := crypto.HashPassword("Admin123!")
	if err != nil {
		return err
	}
	analystHash, err := crypto.HashPassword("Analyst123!")
	if err != nil {
		return err
	}

	now := time.Now()
	users := []bson.M{
		{
			"_id": "admin-uuid-0000-0000-000000000000", "email": "admin@platform.io",
			"password_hash": adminHash, "first_name": "System", "last_name": "Administrator",
			"role": "admin", "clearance_level": 5, "status": "active", "department": "Security",
			"last_login": nil, "created_at": now, "updated_at": now,
		},
		{
			"_id": "analyst-uuid-0000-0000-000000000000", "email": "analyst@platform.io",
			"password_hash": analystHash, "first_name": "John", "last_name": "Analyst",
			"role": "analyst", "clearance_level": 3, "status": "active", "department": "Intelligence",
			"last_login": nil, "created_at": now, "updated_at": now,
		},
	}

	col := db.Collection("users")
	for _, u := range users {
		id := u["_id"]
		delete(u, "_id")
		_, err := col.UpdateOne(ctx,
			bson.M{"_id": id},
			bson.M{"$setOnInsert": mergeID(id, u)},
			options.Update().SetUpsert(true),
		)
		if err != nil {
			return err
		}
	}
	log.Info("seeded users (admin@platform.io / analyst@platform.io)")
	return nil
}

func mergeID(id interface{}, doc bson.M) bson.M {
	out := bson.M{"_id": id}
	for k, v := range doc {
		out[k] = v
	}
	return out
}

func seedIncidents(ctx context.Context, db *mongo.Database, log *zap.Logger) error {
	col := db.Collection("security_incidents")
	if n, _ := col.CountDocuments(ctx, bson.M{}); n > 0 {
		return nil
	}
	now := time.Now()
	strp := func(s string) *string { return &s }
	docs := []interface{}{
		bson.M{"_id": "inc-seed-001", "type": "brute_force", "severity": "critical", "risk_score": 92, "status": "open", "details": bson.M{}, "title": "Credential Stuffing Campaign", "description": "Automated login attempts using a leaked credential list detected against the authentication service.", "source_ip": "91.219.237.19", "affected_assets": []string{"auth-service", "api-gateway"}, "tlp": "RED", "assignee": strp("S. Chen"), "ts": now.Add(-4 * time.Minute)},
		bson.M{"_id": "inc-seed-002", "type": "data_exfil", "severity": "critical", "risk_score": 95, "status": "investigating", "details": bson.M{}, "title": "Credential Leak Detection", "description": "A paste-site scraper flagged a valid admin session token pattern matching this platform's OAuth issuer.", "source_ip": "unknown", "affected_assets": []string{"admin-portal-oauth"}, "tlp": "RED", "assignee": strp("M. Williams"), "ts": now.Add(-22 * time.Minute)},
		bson.M{"_id": "inc-seed-003", "type": "malware", "severity": "critical", "risk_score": 98, "status": "open", "details": bson.M{}, "title": "Ransomware Signature Match", "description": "File integrity monitor detected mass-encryption behaviour consistent with ransomware on file-server-02.", "source_ip": "45.155.205.87", "affected_assets": []string{"file-server-02", "backup-node"}, "tlp": "RED", "assignee": strp("M. Williams"), "ts": now.Add(-47 * time.Minute)},
		bson.M{"_id": "inc-seed-004", "type": "intrusion", "severity": "high", "risk_score": 78, "status": "investigating", "details": bson.M{}, "title": "Privilege Escalation Attempt", "description": "Internal service account attempted to self-assign an admin permission outside the standard IaC pipeline.", "source_ip": "10.0.4.221", "affected_assets": []string{"rbac-service"}, "tlp": "RED", "assignee": strp("H. Al-Farsi"), "ts": now.Add(-1 * time.Hour)},
		bson.M{"_id": "inc-seed-005", "type": "brute_force", "severity": "high", "risk_score": 70, "status": "open", "details": bson.M{}, "title": "Brute Force SSH Probe", "description": "Sustained SSH authentication attempts from a known Tor exit node against the border gateway.", "source_ip": "185.220.101.4", "affected_assets": []string{"border-gateway-01"}, "tlp": "AMBER", "assignee": nil, "ts": now.Add(-5 * time.Minute)},
		bson.M{"_id": "inc-seed-006", "type": "data_exfil", "severity": "high", "risk_score": 74, "status": "open", "details": bson.M{}, "title": "Unusual Data Export Volume", "description": "A single API key exported an abnormally large volume of entity records in a short window.", "source_ip": "172.16.0.44", "affected_assets": []string{"entities-api"}, "tlp": "AMBER", "assignee": strp("N. Petrov"), "ts": now.Add(-2 * time.Hour)},
		bson.M{"_id": "inc-seed-007", "type": "malware", "severity": "high", "risk_score": 81, "status": "investigating", "details": bson.M{}, "title": "Malicious DNS Beacon", "description": "Periodic DNS beaconing from ingest-worker-03 to a domain matching known C2 infrastructure.", "source_ip": "malicious-c2.ru", "affected_assets": []string{"ingest-worker-03"}, "tlp": "RED", "assignee": strp("M. Williams"), "ts": now.Add(-3 * time.Hour)},
		bson.M{"_id": "inc-seed-008", "type": "intrusion", "severity": "high", "risk_score": 65, "status": "resolved", "details": bson.M{}, "title": "SQL Injection Attempt Blocked", "description": "WAF blocked a UNION-based SQL injection attempt against the entities search endpoint.", "source_ip": "103.152.36.9", "affected_assets": []string{"entities-api"}, "tlp": "AMBER", "assignee": strp("S. Chen"), "ts": now.Add(-9 * time.Hour)},
		bson.M{"_id": "inc-seed-009", "type": "impossible_travel", "severity": "medium", "risk_score": 48, "status": "contained", "details": bson.M{}, "title": "Impossible Travel Alert", "description": "Same session token used from two distant locations within a physically impossible time window.", "source_ip": "198.51.100.72", "affected_assets": []string{"a.karimov session"}, "tlp": "AMBER", "assignee": nil, "ts": now.Add(-1 * time.Hour)},
		bson.M{"_id": "inc-seed-010", "type": "anomaly", "severity": "medium", "risk_score": 40, "status": "contained", "details": bson.M{}, "title": "DDoS Pattern on API Gateway", "description": "Volumetric traffic spike from a distributed range; edge rate-limiting engaged automatically.", "source_ip": "203.0.113.10", "affected_assets": []string{"api-gateway"}, "tlp": "GREEN", "assignee": nil, "ts": now.Add(-5 * time.Hour)},
		bson.M{"_id": "inc-seed-011", "type": "policy_violation", "severity": "low", "risk_score": 15, "status": "resolved", "details": bson.M{}, "title": "Policy Violation: Clipboard Export", "description": "User copied classification-marked data to clipboard on a device without a DLP agent installed.", "source_ip": "10.0.1.55", "affected_assets": []string{"analyst-workstation-12"}, "tlp": "WHITE", "assignee": strp("J. O'Brien"), "ts": now.Add(-24 * time.Hour)},
	}
	if _, err := col.InsertMany(ctx, docs); err != nil {
		return err
	}
	log.Info("seeded security incidents", zap.Int("count", len(docs)))
	return nil
}

func seedVulnerabilities(ctx context.Context, db *mongo.Database, log *zap.Logger) error {
	col := db.Collection("vulnerabilities")
	if n, _ := col.CountDocuments(ctx, bson.M{}); n > 0 {
		return nil
	}
	now := time.Now()
	cve := func(s string) *string { return &s }
	docs := []interface{}{
		bson.M{"_id": "vuln-seed-001", "cve_id": cve("CVE-2024-6387"), "title": "OpenSSH regreSSHion — Remote Code Execution", "severity": "critical", "cvss_score": 9.8, "status": "open", "affected_asset": "bastion-hosts (x4)", "component": "openssh-server 8.9p1", "description": "Signal handler race condition allows unauthenticated remote code execution as root on glibc-based systems.", "remediation": "Upgrade to OpenSSH 9.8 or apply vendor backport patch.", "discovered_at": now.Add(-3 * 24 * time.Hour), "updated_at": now},
		bson.M{"_id": "vuln-seed-002", "cve_id": cve("CVE-2024-3094"), "title": "XZ Utils Supply-Chain Backdoor", "severity": "critical", "cvss_score": 10.0, "status": "patching", "affected_asset": "ingest-worker (x6)", "component": "liblzma 5.6.1", "description": "Malicious code injected into the xz build process allows SSH authentication bypass.", "remediation": "Pin liblzma to 5.4.x and rebuild ingest-worker images.", "discovered_at": now.Add(-6 * 24 * time.Hour), "updated_at": now},
		bson.M{"_id": "vuln-seed-003", "cve_id": cve("CVE-2024-21626"), "title": "runc Container Breakout", "severity": "critical", "cvss_score": 8.6, "status": "patching", "affected_asset": "k8s-worker-pool", "component": "runc 1.1.11", "description": "File descriptor leak allows a malicious container to access the host filesystem.", "remediation": "Upgrade container runtime to runc 1.1.12+.", "discovered_at": now.Add(-4 * 24 * time.Hour), "updated_at": now},
		bson.M{"_id": "vuln-seed-004", "cve_id": cve("CVE-2023-44487"), "title": "HTTP/2 Rapid Reset DoS", "severity": "high", "cvss_score": 7.5, "status": "mitigated", "affected_asset": "api-gateway", "component": "gin/http2 stack", "description": "Rapid stream creation/cancellation can exhaust server resources, causing denial of service.", "remediation": "Stream concurrency limits and connection-level rate limiting deployed at the edge.", "discovered_at": now.Add(-12 * 24 * time.Hour), "updated_at": now},
		bson.M{"_id": "vuln-seed-005", "cve_id": nil, "title": "Exposed Debug Metrics Endpoint", "severity": "high", "cvss_score": 7.2, "status": "mitigated", "affected_asset": "monitoring-service", "component": "internal /metrics route", "description": "/metrics endpoint reachable without authentication from the internal network.", "remediation": "Restricted to the monitoring VPC range and added bearer-token auth.", "discovered_at": now.Add(-9 * 24 * time.Hour), "updated_at": now},
		bson.M{"_id": "vuln-seed-006", "cve_id": cve("CVE-2023-4863"), "title": "libwebp Heap Buffer Overflow", "severity": "high", "cvss_score": 8.8, "status": "resolved", "affected_asset": "image-thumbnailer", "component": "libwebp 1.3.1", "description": "Crafted WebP images can trigger a heap overflow leading to potential remote code execution.", "remediation": "Upgraded to libwebp 1.3.2 across all document-processing containers.", "discovered_at": now.Add(-30 * 24 * time.Hour), "updated_at": now},
		bson.M{"_id": "vuln-seed-007", "cve_id": nil, "title": "Weak Password Policy on Service Accounts", "severity": "medium", "cvss_score": 6.1, "status": "accepted_risk", "affected_asset": "IAM / service accounts", "component": "auth-service policy config", "description": "Legacy service accounts are exempt from the minimum password policy.", "remediation": "Scheduled for rotation to certificate-based auth in Q4 migration.", "discovered_at": now.Add(-18 * 24 * time.Hour), "updated_at": now},
		bson.M{"_id": "vuln-seed-008", "cve_id": nil, "title": "Outdated TLS Cipher Suite on Legacy Endpoint", "severity": "medium", "cvss_score": 5.3, "status": "open", "affected_asset": "legacy-report-svc", "component": "nginx 1.18 TLS config", "description": "Endpoint still negotiates TLS 1.1 and CBC cipher suites for backward compatibility.", "remediation": "Consumer notified of TLS 1.3-only cutover date.", "discovered_at": now.Add(-5 * 24 * time.Hour), "updated_at": now},
	}
	if _, err := col.InsertMany(ctx, docs); err != nil {
		return err
	}
	log.Info("seeded vulnerabilities", zap.Int("count", len(docs)))
	return nil
}

func seedRBAC(ctx context.Context, db *mongo.Database, log *zap.Logger) error {
	perms := db.Collection("permissions")
	if n, _ := perms.CountDocuments(ctx, bson.M{}); n > 0 {
		return nil
	}

	// permission_id -> {resource, action, name}
	type perm struct{ id, resource, action, name string }
	catalog := []perm{
		{"perm-ent-read", "entities", "read", "Read Entities"},
		{"perm-ent-write", "entities", "write", "Write Entities"},
		{"perm-ent-delete", "entities", "delete", "Delete Entities"},
		{"perm-case-read", "cases", "read", "Read Cases"},
		{"perm-case-write", "cases", "write", "Write Cases"},
		{"perm-audit-read", "audit", "read", "Read Audit Logs"},
		{"perm-audit-export", "audit", "export", "Export Audit"},
		{"perm-user-admin", "users", "admin", "Manage Users"},
		{"perm-role-admin", "roles", "admin", "Manage Roles"},
		{"perm-sec-read", "security", "read", "View Security"},
		{"perm-sec-manage", "security", "manage", "Manage Security"},
		{"perm-mon-read", "monitoring", "read", "View Monitoring"},
		{"perm-agent-manage", "agents", "manage", "Manage Agents"},
	}
	permDocs := make([]interface{}, 0, len(catalog))
	for _, p := range catalog {
		permDocs = append(permDocs, bson.M{"_id": p.id, "resource": p.resource, "action": p.action, "name": p.name})
	}
	if _, err := perms.InsertMany(ctx, permDocs); err != nil {
		return err
	}

	all := make([]string, len(catalog))
	for i, p := range catalog {
		all[i] = p.id
	}
	now := time.Now()
	roles := []struct {
		id, name, desc string
		perms          []string
	}{
		{"role-admin", "admin", "Full system access with all administrative privileges", all},
		{"role-analyst", "analyst", "Access to intelligence data, entities and cases", []string{"perm-ent-read", "perm-ent-write", "perm-case-read", "perm-case-write", "perm-sec-read", "perm-mon-read"}},
		{"role-viewer", "viewer", "Read-only access to non-sensitive data", []string{"perm-ent-read", "perm-case-read"}},
		{"role-operator", "operator", "Operational access including agent management", []string{"perm-ent-read", "perm-ent-write", "perm-case-read", "perm-agent-manage", "perm-mon-read"}},
		{"role-auditor", "auditor", "Access to audit logs and compliance reporting", []string{"perm-ent-read", "perm-case-read", "perm-audit-read", "perm-audit-export", "perm-mon-read"}},
	}
	roleDocs := make([]interface{}, 0, len(roles))
	var rpDocs []interface{}
	for _, r := range roles {
		roleDocs = append(roleDocs, bson.M{"_id": r.id, "name": r.name, "description": r.desc, "created_at": now})
		for _, pid := range r.perms {
			rpDocs = append(rpDocs, bson.M{"role_id": r.id, "permission_id": pid})
		}
	}
	if _, err := db.Collection("roles").InsertMany(ctx, roleDocs); err != nil {
		return err
	}
	if _, err := db.Collection("role_permissions").InsertMany(ctx, rpDocs); err != nil {
		return err
	}
	log.Info("seeded RBAC", zap.Int("permissions", len(catalog)), zap.Int("roles", len(roles)))
	return nil
}

func seedBlocklist(ctx context.Context, db *mongo.Database, log *zap.Logger) error {
	col := db.Collection("blocklist")
	if n, _ := col.CountDocuments(ctx, bson.M{}); n > 0 {
		return nil
	}
	now := time.Now()
	docs := []interface{}{
		bson.M{"_id": "blk-seed-001", "value": "185.220.101.4", "type": "ip", "reason": "Tor exit node — sustained SSH brute-force probing", "hit_count": 214, "added_by": "System (auto-rule)", "expires_at": nil, "created_at": now.Add(-24 * time.Hour)},
		bson.M{"_id": "blk-seed-002", "value": "malicious-c2.ru", "type": "domain", "reason": "Matches known C2 infrastructure — DNS beacon pattern", "hit_count": 58, "added_by": "M. Williams", "expires_at": nil, "created_at": now.Add(-48 * time.Hour)},
		bson.M{"_id": "blk-seed-003", "value": "45.155.205.87", "type": "ip", "reason": "Ransomware staging host", "hit_count": 6, "added_by": "System (auto-rule)", "expires_at": nil, "created_at": now.Add(-40 * time.Minute)},
		bson.M{"_id": "blk-seed-004", "value": "91.219.237.19", "type": "ip", "reason": "Credential stuffing botnet node", "hit_count": 4812, "added_by": "S. Chen", "expires_at": nil, "created_at": now.Add(-3 * time.Minute)},
		bson.M{"_id": "blk-seed-005", "value": "103.152.36.9", "type": "ip", "reason": "SQL injection scanner — WAF signature match", "hit_count": 31, "added_by": "System (auto-rule)", "expires_at": nil, "created_at": now.Add(-9 * time.Hour)},
	}
	if _, err := col.InsertMany(ctx, docs); err != nil {
		return err
	}
	log.Info("seeded blocklist", zap.Int("count", len(docs)))
	return nil
}
