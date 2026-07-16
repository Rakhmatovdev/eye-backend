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
	if err := seedEntities(ctx, db, log); err != nil {
		return err
	}
	if err := seedEvents(ctx, db, log); err != nil {
		return err
	}
	if err := seedSensors(ctx, db, log); err != nil {
		return err
	}
	if err := seedMilitary(ctx, db, log); err != nil {
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

// seedEntities inserts a small intelligence graph with geo coordinates in each
// entity's free-form `properties` (lat/lng). This powers Search, the Graph view
// and — because the coordinates are present — the Geospatial Map. A handful of
// relationships are added so /graph/expand returns edges. Idempotent (only when
// the collection is empty).
func seedEntities(ctx context.Context, db *mongo.Database, log *zap.Logger) error {
	col := db.Collection("entities")
	now := time.Now()
	ent := func(id, typ, class string, props bson.M) bson.M {
		return bson.M{"_id": id, "type": typ, "classification": class, "properties": props,
			"source_id": "seed", "created_at": now, "updated_at": now}
	}
	docs := []interface{}{
		ent("ent-001", "person", "confidential", bson.M{"name": "Alisher Karimov", "lat": 41.2995, "lng": 69.2401, "address": "Tashkent, Uzbekistan", "nationality": "Uzbekistani", "risk_score": 78, "tags": "target,financial-crime"}),
		ent("ent-002", "person", "secret", bson.M{"name": "Zhang Wei", "lat": 43.2220, "lng": 76.8512, "address": "Almaty, Kazakhstan", "nationality": "Chinese", "risk_score": 91, "tags": "foreign-national,high-value"}),
		ent("ent-003", "person", "confidential", bson.M{"name": "Rustam Nazarov", "lat": 39.6542, "lng": 66.9597, "address": "Samarkand, Uzbekistan", "nationality": "Uzbekistani", "risk_score": 62, "tags": "informant,logistics"}),
		ent("ent-005", "person", "confidential", bson.M{"name": "Bekzod Toshmatov", "lat": 40.7841, "lng": 72.3417, "address": "Fergana, Uzbekistan", "nationality": "Uzbekistani", "risk_score": 55, "tags": "border-crossing,smuggling"}),
		ent("ent-007", "person", "secret", bson.M{"name": "Sergei Volkov", "lat": 42.3417, "lng": 69.5901, "address": "Shymkent, Kazakhstan", "nationality": "Russian", "risk_score": 85, "tags": "organized-crime"}),
		ent("ent-009", "person", "secret", bson.M{"name": "Timur Umarov", "lat": 38.5598, "lng": 68.7739, "address": "Dushanbe, Tajikistan", "nationality": "Tajik", "risk_score": 93, "tags": "target,narcotics,high-priority"}),
		ent("ent-011", "person", "secret", bson.M{"name": "Hassan Al-Rashidi", "lat": 41.2850, "lng": 69.2100, "address": "Tashkent, Uzbekistan", "nationality": "UAE", "risk_score": 88, "tags": "terrorism-finance,high-value"}),
		ent("ent-013", "organization", "confidential", bson.M{"name": "Silk Road Trading LLC", "lat": 41.3200, "lng": 69.2600, "address": "Tashkent, Uzbekistan", "risk_score": 74, "tags": "shell-company,import-export"}),
		ent("ent-014", "organization", "secret", bson.M{"name": "Dragon Capital Investment", "lat": 43.2220, "lng": 76.8512, "address": "Almaty, Kazakhstan", "risk_score": 89, "tags": "foreign-entity,prc-linked"}),
		ent("ent-018", "organization", "secret", bson.M{"name": "Gulf Horizon Investments", "lat": 25.2048, "lng": 55.2708, "address": "Dubai, UAE", "risk_score": 82, "tags": "uae-linked,terrorism-finance"}),
		ent("ent-019", "organization", "confidential", bson.M{"name": "CryptoAsia Exchange", "lat": 42.8746, "lng": 74.5698, "address": "Bishkek, Kyrgyzstan", "risk_score": 71, "tags": "cryptocurrency,money-laundering"}),
		ent("ent-025", "location", "public", bson.M{"name": "Tashkent International Airport", "lat": 41.2579, "lng": 69.2812, "address": "Tashkent, Uzbekistan", "tags": "border-control,transit"}),
		ent("ent-027", "location", "confidential", bson.M{"name": "Dostuk Border Crossing", "lat": 40.7700, "lng": 72.8000, "address": "UZ-KG border", "tags": "border,crossing"}),
		ent("ent-052", "location", "confidential", bson.M{"name": "Termez Rail Terminal", "lat": 37.2242, "lng": 67.2783, "address": "Termez, Uzbekistan", "tags": "border,rail,cargo-transit"}),
	}
	// Upsert by _id so the curated geo entities always exist even if other
	// (manually created) entities are already present in the collection.
	if err := upsertByID(ctx, col, docs); err != nil {
		return err
	}

	rel := func(from, to, typ string) bson.M {
		return bson.M{"_id": "rel-" + from + "-" + to, "entity_id_from": from, "entity_id_to": to,
			"type": typ, "properties": bson.M{"label": typ}, "created_at": now}
	}
	rels := []interface{}{
		rel("ent-001", "ent-013", "director_of"),
		rel("ent-002", "ent-014", "director_of"),
		rel("ent-013", "ent-014", "subsidiary_of"),
		rel("ent-001", "ent-002", "associate"),
		rel("ent-003", "ent-001", "associate"),
		rel("ent-011", "ent-018", "director_of"),
		rel("ent-009", "ent-019", "uses"),
		rel("ent-005", "ent-027", "crossed"),
	}
	if err := upsertByID(ctx, db.Collection("relationships"), rels); err != nil {
		return err
	}
	log.Info("seeded entities + relationships", zap.Int("entities", len(docs)), zap.Int("relationships", len(rels)))
	return nil
}

// seedSensors inserts a synthetic surveillance sensor network (cameras, drones,
// radar, SIGINT collectors) plus detections that identify seeded entities — the
// "which sensor saw whom, where, when" feed that powers person-finding. All data
// is fictional demo data. Idempotent (only when empty).
func seedSensors(ctx context.Context, db *mongo.Database, log *zap.Logger) error {
	col := db.Collection("sensors")
	if n, _ := col.CountDocuments(ctx, bson.M{}); n > 0 {
		return nil
	}
	now := time.Now()
	sen := func(id, name, typ, status string, lat, lng float64, area string, radius int, res, class string) bson.M {
		return bson.M{"_id": id, "name": name, "type": typ, "status": status, "lat": lat, "lng": lng,
			"area": area, "coverage_radius": radius, "resolution": res, "classification": class,
			"feed_url": "sim://" + id, "last_heartbeat": now.Add(-time.Duration(radius%7) * time.Minute), "created_at": now}
	}
	sensors := []interface{}{
		sen("cam-001", "TAS Airport — Terminal Cam A", "camera", "online", 41.2579, 69.2812, "Tashkent Intl Airport", 300, "4K", "confidential"),
		sen("cam-002", "TAS Airport — Passport Control", "camera", "online", 41.2585, 69.2805, "Tashkent Intl Airport", 150, "4K", "secret"),
		sen("cam-003", "Dostuk Border — Lane 3 ANPR", "camera", "online", 40.7700, 69.2900, "Dostuk Border Crossing", 120, "1080p ANPR", "confidential"),
		sen("cam-004", "Yunusabad — Silk Road Office", "camera", "degraded", 41.3200, 69.2600, "Tashkent — Yunusabad", 80, "1080p", "secret"),
		sen("cam-005", "Almaty BC — Dragon Capital Lobby", "camera", "online", 43.2220, 76.8512, "Almaty Business Center", 60, "1080p", "secret"),
		sen("cam-006", "Samarkand — Registon Sq.", "camera", "online", 39.6542, 66.9597, "Samarkand", 200, "4K", "internal"),
		sen("cam-007", "Termez Rail — Gate 2", "camera", "offline", 37.2242, 67.2783, "Termez Rail Terminal", 180, "1080p", "confidential"),
		sen("drn-001", "UAV Reaper-7 (patrol)", "drone", "online", 40.7841, 72.3417, "Fergana Valley", 5000, "EO/IR gimbal", "secret"),
		sen("drn-002", "UAV Shadow-3 (loiter)", "drone", "online", 38.5598, 68.7739, "Dushanbe approach", 4000, "EO/IR gimbal", "secret"),
		sen("rad-001", "Border Radar North", "radar", "online", 42.3417, 69.5901, "Shymkent sector", 30000, "S-band", "confidential"),
		sen("sig-001", "SIGINT Collector Alpha", "sigint", "online", 41.2995, 69.2401, "Tashkent metro", 15000, "COMINT", "secret"),
		sen("sig-002", "SIGINT Collector Bravo", "sigint", "degraded", 42.8746, 74.5698, "Bishkek", 12000, "COMINT", "secret"),
	}
	if _, err := col.InsertMany(ctx, sensors); err != nil {
		return err
	}

	dcol := db.Collection("detections")
	det := func(id, sensorID, sensorName, entityID, entityName, kind string, conf, lat, lng float64, area string, ago time.Duration) bson.M {
		return bson.M{"_id": id, "sensor_id": sensorID, "sensor_name": sensorName, "entity_id": entityID,
			"entity_name": entityName, "kind": kind, "confidence": conf, "lat": lat, "lng": lng,
			"area": area, "timestamp": now.Add(-ago)}
	}
	detections := []interface{}{
		det("det-001", "cam-002", "TAS Airport — Passport Control", "ent-001", "Alisher Karimov", "face_match", 0.96, 41.2585, 69.2805, "Tashkent Intl Airport", 2*time.Hour),
		det("det-002", "cam-001", "TAS Airport — Terminal Cam A", "ent-011", "Hassan Al-Rashidi", "face_match", 0.91, 41.2579, 69.2812, "Tashkent Intl Airport", 5*time.Hour),
		det("det-003", "cam-003", "Dostuk Border — Lane 3 ANPR", "ent-005", "Bekzod Toshmatov", "plate_match", 0.99, 40.7700, 69.2900, "Dostuk Border Crossing", 8*time.Hour),
		det("det-004", "cam-005", "Almaty BC — Dragon Capital Lobby", "ent-002", "Zhang Wei", "face_match", 0.88, 43.2220, 76.8512, "Almaty Business Center", 11*time.Hour),
		det("det-005", "sig-001", "SIGINT Collector Alpha", "ent-001", "Alisher Karimov", "signal", 0.82, 41.2995, 69.2401, "Tashkent metro", 13*time.Hour),
		det("det-006", "cam-004", "Yunusabad — Silk Road Office", "ent-001", "Alisher Karimov", "face_match", 0.79, 41.3200, 69.2600, "Tashkent — Yunusabad", 20*time.Hour),
		det("det-007", "drn-002", "UAV Shadow-3 (loiter)", "ent-009", "Timur Umarov", "thermal", 0.71, 38.5598, 68.7739, "Dushanbe approach", 26*time.Hour),
		det("det-008", "cam-006", "Samarkand — Registon Sq.", "ent-003", "Rustam Nazarov", "face_match", 0.85, 39.6542, 66.9597, "Samarkand", 30*time.Hour),
		det("det-009", "sig-002", "SIGINT Collector Bravo", "ent-019", "CryptoAsia Exchange", "signal", 0.68, 42.8746, 74.5698, "Bishkek", 34*time.Hour),
		det("det-010", "drn-001", "UAV Reaper-7 (patrol)", "ent-005", "Bekzod Toshmatov", "thermal", 0.64, 40.7841, 72.3417, "Fergana Valley", 40*time.Hour),
		det("det-011", "cam-003", "Dostuk Border — Lane 3 ANPR", "", "Unidentified vehicle", "plate_match", 0.55, 40.7700, 69.2900, "Dostuk Border Crossing", 3*time.Hour),
		det("det-012", "cam-002", "TAS Airport — Passport Control", "ent-007", "Sergei Volkov", "face_match", 0.93, 41.2585, 69.2805, "Tashkent Intl Airport", 46*time.Hour),
		det("det-013", "rad-001", "Border Radar North", "", "Unattributed track", "motion", 0.60, 42.3417, 69.5901, "Shymkent sector", 1*time.Hour),
		det("det-014", "cam-005", "Almaty BC — Dragon Capital Lobby", "ent-002", "Zhang Wei", "face_match", 0.90, 43.2220, 76.8512, "Almaty Business Center", 52*time.Hour),
		det("det-015", "sig-001", "SIGINT Collector Alpha", "ent-011", "Hassan Al-Rashidi", "signal", 0.77, 41.2850, 69.2100, "Tashkent metro", 6*time.Hour),
		det("det-016", "drn-002", "UAV Shadow-3 (loiter)", "ent-009", "Timur Umarov", "thermal", 0.74, 38.5598, 68.7739, "Dushanbe approach", 15*time.Hour),
	}
	if _, err := dcol.InsertMany(ctx, detections); err != nil {
		return err
	}
	log.Info("seeded sensors + detections", zap.Int("sensors", len(sensors)), zap.Int("detections", len(detections)))
	return nil
}

// seedMilitary inserts a synthetic Common Operating Picture: friendly units,
// hostile/suspect/unknown threat tracks, and an operations board — all fictional
// demo data for the tactical command view. Idempotent (only when empty).
func seedMilitary(ctx context.Context, db *mongo.Database, log *zap.Logger) error {
	ucol := db.Collection("mil_units")
	if n, _ := ucol.CountDocuments(ctx, bson.M{}); n > 0 {
		return nil
	}
	now := time.Now()
	unit := func(id, cs, name, typ, domain, status, readiness string, lat, lng float64, strength, heading int, speed float64) bson.M {
		return bson.M{"_id": id, "callsign": cs, "name": name, "type": typ, "domain": domain,
			"status": status, "readiness": readiness, "lat": lat, "lng": lng, "strength": strength,
			"heading": heading, "speed": speed, "updated_at": now}
	}
	units := []interface{}{
		unit("u-001", "EAGLE-6", "Task Force HQ", "hq", "land", "active", "green", 41.3111, 69.2797, 45, 0, 0),
		unit("u-002", "STEEL-1", "1st Armored Coy", "armor", "land", "moving", "green", 40.9000, 71.7500, 120, 210, 32),
		unit("u-003", "VIPER-2", "Recon Platoon", "recon", "land", "active", "amber", 40.7900, 72.3500, 28, 95, 18),
		unit("u-004", "GHOST-9", "SOF Detachment", "infantry", "land", "engaged", "green", 38.6000, 68.8000, 16, 140, 6),
		unit("u-005", "HAWK-1", "UAV Sqn (Reaper)", "uav", "air", "active", "green", 40.7841, 72.3417, 3, 270, 240),
		unit("u-006", "FALCON-3", "CAS Flight", "air", "air", "standby", "amber", 41.2600, 69.2000, 2, 0, 0),
		unit("u-007", "ANVIL-4", "Artillery Battery", "logistics", "land", "active", "green", 40.8500, 71.9000, 60, 0, 0),
		unit("u-008", "SHIELD-7", "Border QRF", "infantry", "land", "standby", "green", 40.7700, 72.8000, 40, 0, 0),
	}
	if _, err := ucol.InsertMany(ctx, units); err != nil {
		return err
	}

	tcol := db.Collection("mil_threats")
	threat := func(id, desig, typ, class, level string, lat, lng float64, heading int, speed, conf float64, entityID string, ago time.Duration) bson.M {
		return bson.M{"_id": id, "designation": desig, "type": typ, "classification": class,
			"threat_level": level, "lat": lat, "lng": lng, "heading": heading, "speed": speed,
			"confidence": conf, "entity_id": entityID, "last_seen": now.Add(-ago)}
	}
	threats := []interface{}{
		threat("t-001", "HOSTILE-01 (convoy)", "convoy", "hostile", "critical", 38.9700, 70.1839, 300, 45, 0.88, "ent-009", 12*time.Minute),
		threat("t-002", "SUSPECT-04 (UAV)", "uav", "suspect", "high", 40.7500, 72.6000, 250, 120, 0.72, "", 5*time.Minute),
		threat("t-003", "HOSTILE-02 (armor)", "armor", "hostile", "high", 39.0500, 70.3000, 290, 25, 0.81, "", 20*time.Minute),
		threat("t-004", "UNKNOWN-07 (track)", "unknown", "unknown", "medium", 42.3000, 69.6000, 180, 60, 0.55, "", 3*time.Minute),
		threat("t-005", "SUSPECT-09 (convoy)", "convoy", "suspect", "medium", 37.3000, 67.4000, 20, 40, 0.63, "ent-005", 40*time.Minute),
		threat("t-006", "HOSTILE-03 (arty)", "artillery", "hostile", "critical", 38.8000, 69.9000, 0, 0, 0.79, "", 8*time.Minute),
	}
	if _, err := tcol.InsertMany(ctx, threats); err != nil {
		return err
	}

	mcol := db.Collection("mil_missions")
	mission := func(id, name, status, prio, obj, area string, unitsList []string, progress int, startsAgo time.Duration) bson.M {
		return bson.M{"_id": id, "name": name, "status": status, "priority": prio, "objective": obj,
			"area": area, "assigned_units": unitsList, "progress": progress,
			"starts_at": now.Add(-startsAgo), "updated_at": now}
	}
	missions := []interface{}{
		mission("m-001", "OP SILK SENTINEL", "active", "immediate", "Interdict HOSTILE-01 narcotics convoy before border crossing.", "Dushanbe–Termez corridor", []string{"u-004", "u-005"}, 65, 6*time.Hour),
		mission("m-002", "OP IRON GATE", "active", "priority", "Screen Fergana valley approaches; maintain COP on suspect UAV activity.", "Fergana Valley", []string{"u-002", "u-003", "u-007"}, 40, 10*time.Hour),
		mission("m-003", "OP NIGHT LEDGER", "planning", "priority", "Prepare cordon-and-search of Silk Road Trading premises pending warrant.", "Tashkent — Yunusabad", []string{"u-001", "u-008"}, 15, 2*time.Hour),
		mission("m-004", "OP CLEAR SKY", "on_hold", "routine", "CAS on-call posture for QRF tasking.", "Tashkent sector", []string{"u-006"}, 0, 1*time.Hour),
		mission("m-005", "OP RIVER WATCH", "complete", "routine", "Prior surveillance sweep of Termez rail terminal — complete.", "Termez Rail Terminal", []string{"u-008"}, 100, 48*time.Hour),
	}
	if _, err := mcol.InsertMany(ctx, missions); err != nil {
		return err
	}
	log.Info("seeded military COP", zap.Int("units", len(units)), zap.Int("threats", len(threats)), zap.Int("missions", len(missions)))
	return nil
}

// upsertByID upserts each bson.M doc (which must carry an `_id`) by its id using
// $setOnInsert, so re-running seed neither duplicates nor overwrites edits.
func upsertByID(ctx context.Context, col *mongo.Collection, docs []interface{}) error {
	for _, d := range docs {
		doc := d.(bson.M)
		id := doc["_id"]
		if _, err := col.UpdateOne(ctx,
			bson.M{"_id": id},
			bson.M{"$setOnInsert": doc},
			options.Update().SetUpsert(true),
		); err != nil {
			return err
		}
	}
	return nil
}

// seedEvents inserts time-stamped events for the Timeline / Time Analysis view.
// entity_id values reference the seeded entities. Timestamps are relative to now
// so the timeline reads as recent activity. Idempotent (only when empty).
func seedEvents(ctx context.Context, db *mongo.Database, log *zap.Logger) error {
	col := db.Collection("events")
	if n, _ := col.CountDocuments(ctx, bson.M{}); n > 0 {
		return nil
	}
	now := time.Now()
	ev := func(id, entityID, typ, title, desc, loc string, ago time.Duration) bson.M {
		return bson.M{"_id": id, "entity_id": entityID, "type": typ, "title": title,
			"description": desc, "location": loc, "timestamp": now.Add(-ago), "created_at": now}
	}
	docs := []interface{}{
		ev("ev-001", "ent-001", "travel", "Departed Tashkent Airport", "Crossed border on flight UZ-204 to Almaty.", "Tashkent, UZ", 30*24*time.Hour),
		ev("ev-002", "ent-001", "travel", "Arrived Almaty Airport", "Border check and visa scan cleared.", "Almaty, KZ", 30*24*time.Hour-3*time.Hour),
		ev("ev-003", "ent-013", "financial", "Suspicious Wire Transfer", "SWIFT transfer of $480,000 to Dragon Capital Investment.", "Tashkent, UZ", 26*24*time.Hour),
		ev("ev-004", "ent-005", "telecom", "SIM Handshake Registered", "SIM +998951234567 active on cell tower near Dostuk crossing.", "Fergana, UZ", 22*24*time.Hour),
		ev("ev-005", "ent-001", "meeting", "Physical Meeting Observed", "Surveillance reports a meeting between Karimov and Zhang Wei.", "Almaty, KZ", 20*24*time.Hour),
		ev("ev-006", "ent-009", "financial", "Hawala Transfer Flagged", "$150,000-equivalent informal value transfer toward an Afghan entity.", "Dushanbe, TJ", 16*24*time.Hour),
		ev("ev-007", "ent-002", "travel", "Roaming Detected", "Device roamed across UZ, KZ, KG within 48 hours.", "Almaty, KZ", 14*24*time.Hour),
		ev("ev-008", "ent-019", "financial", "Crypto Transfer", "12.4 BTC (~$840k) routed through CryptoAsia Exchange; mixing detected.", "Bishkek, KG", 11*24*time.Hour),
		ev("ev-009", "ent-011", "travel", "Repeat Visitor Alert", "8th recorded visit to Tashkent this year.", "Tashkent, UZ", 7*24*time.Hour),
		ev("ev-010", "ent-005", "border", "Border Crossing", "Vehicle 01A123BC crossed at Dostuk checkpoint.", "Dostuk, UZ-KG", 4*24*time.Hour),
		ev("ev-011", "ent-052", "cargo", "Flagged Rail Shipment", "Container manifest mismatch on the Termez–Afghan corridor.", "Termez, UZ", 2*24*time.Hour),
		ev("ev-012", "ent-001", "meeting", "Encrypted Call Intercept", "Signal intercept: discussion of 'shipment' arrival and crypto payment.", "Tashkent, UZ", 18*time.Hour),
	}
	if _, err := col.InsertMany(ctx, docs); err != nil {
		return err
	}
	log.Info("seeded timeline events", zap.Int("count", len(docs)))
	return nil
}
