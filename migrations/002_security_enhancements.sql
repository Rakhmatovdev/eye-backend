-- 002_security_enhancements.sql
-- Enriches the Security Center data model: incident context, vulnerability
-- tracking, and blocklist hit metrics. Also seeds realistic demo data so the
-- Security Center is populated on first run.

ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS title VARCHAR(255) NOT NULL DEFAULT 'Untitled Incident';
ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS source_ip VARCHAR(64) NOT NULL DEFAULT 'unknown';
ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS affected_assets JSONB NOT NULL DEFAULT '[]';
ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS tlp VARCHAR(10) NOT NULL DEFAULT 'AMBER';
ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS assignee VARCHAR(255);

ALTER TABLE blocklist ADD COLUMN IF NOT EXISTS hit_count INT NOT NULL DEFAULT 0;
ALTER TABLE blocklist ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
ALTER TABLE blocklist ADD COLUMN IF NOT EXISTS added_by VARCHAR(255) NOT NULL DEFAULT 'System (auto-rule)';

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id VARCHAR(36) PRIMARY KEY,
    cve_id VARCHAR(50),
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    cvss_score NUMERIC(3,1) NOT NULL DEFAULT 0,
    status VARCHAR(30) NOT NULL DEFAULT 'open',
    affected_asset VARCHAR(255) NOT NULL,
    component VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    discovered_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Seed security incidents (idempotent — only inserts when table is empty)
INSERT INTO security_incidents (id, type, severity, risk_score, status, details, title, description, source_ip, affected_assets, tlp, assignee, ts)
SELECT * FROM (VALUES
    ('inc-seed-001', 'brute_force', 'critical', 92, 'open', '{}'::jsonb,
        'Credential Stuffing Campaign', 'Automated login attempts using a leaked credential list detected against the authentication service.',
        '91.219.237.19', '["auth-service","api-gateway"]'::jsonb, 'RED', 'S. Chen', NOW() - INTERVAL '4 minutes'),
    ('inc-seed-002', 'data_exfil', 'critical', 95, 'investigating', '{}'::jsonb,
        'Credential Leak Detection', 'A paste-site scraper flagged a valid admin session token pattern matching this platform''s OAuth issuer.',
        'unknown', '["admin-portal-oauth"]'::jsonb, 'RED', 'M. Williams', NOW() - INTERVAL '22 minutes'),
    ('inc-seed-003', 'malware', 'critical', 98, 'open', '{}'::jsonb,
        'Ransomware Signature Match', 'File integrity monitor detected mass-encryption behaviour consistent with ransomware on file-server-02.',
        '45.155.205.87', '["file-server-02","backup-node"]'::jsonb, 'RED', 'M. Williams', NOW() - INTERVAL '47 minutes'),
    ('inc-seed-004', 'intrusion', 'high', 78, 'investigating', '{}'::jsonb,
        'Privilege Escalation Attempt', 'Internal service account attempted to self-assign an admin permission outside the standard IaC pipeline.',
        '10.0.4.221', '["rbac-service"]'::jsonb, 'RED', 'H. Al-Farsi', NOW() - INTERVAL '1 hour'),
    ('inc-seed-005', 'brute_force', 'high', 70, 'open', '{}'::jsonb,
        'Brute Force SSH Probe', 'Sustained SSH authentication attempts from a known Tor exit node against the border gateway.',
        '185.220.101.4', '["border-gateway-01"]'::jsonb, 'AMBER', NULL, NOW() - INTERVAL '5 minutes'),
    ('inc-seed-006', 'data_exfil', 'high', 74, 'open', '{}'::jsonb,
        'Unusual Data Export Volume', 'A single API key exported an abnormally large volume of entity records in a short window.',
        '172.16.0.44', '["entities-api"]'::jsonb, 'AMBER', 'N. Petrov', NOW() - INTERVAL '2 hours'),
    ('inc-seed-007', 'malware', 'high', 81, 'investigating', '{}'::jsonb,
        'Malicious DNS Beacon', 'Periodic DNS beaconing from ingest-worker-03 to a domain matching known C2 infrastructure.',
        'malicious-c2.ru', '["ingest-worker-03"]'::jsonb, 'RED', 'M. Williams', NOW() - INTERVAL '3 hours'),
    ('inc-seed-008', 'intrusion', 'high', 65, 'resolved', '{}'::jsonb,
        'SQL Injection Attempt Blocked', 'WAF blocked a UNION-based SQL injection attempt against the entities search endpoint.',
        '103.152.36.9', '["entities-api"]'::jsonb, 'AMBER', 'S. Chen', NOW() - INTERVAL '9 hours'),
    ('inc-seed-009', 'impossible_travel', 'medium', 48, 'contained', '{}'::jsonb,
        'Impossible Travel Alert', 'Same session token used from two distant locations within a physically impossible time window.',
        '198.51.100.72', '["a.karimov session"]'::jsonb, 'AMBER', NULL, NOW() - INTERVAL '1 hour'),
    ('inc-seed-010', 'anomaly', 'medium', 40, 'contained', '{}'::jsonb,
        'DDoS Pattern on API Gateway', 'Volumetric traffic spike from a distributed range; edge rate-limiting engaged automatically.',
        '203.0.113.0/24', '["api-gateway"]'::jsonb, 'GREEN', NULL, NOW() - INTERVAL '5 hours'),
    ('inc-seed-011', 'policy_violation', 'low', 15, 'resolved', '{}'::jsonb,
        'Policy Violation: Clipboard Export', 'User copied classification-marked data to clipboard on a device without a DLP agent installed.',
        '10.0.1.55', '["analyst-workstation-12"]'::jsonb, 'WHITE', 'J. O''Brien', NOW() - INTERVAL '1 day')
) AS seed(id, type, severity, risk_score, status, details, title, description, source_ip, affected_assets, tlp, assignee, ts)
WHERE NOT EXISTS (SELECT 1 FROM security_incidents LIMIT 1);

-- Seed vulnerabilities
INSERT INTO vulnerabilities (id, cve_id, title, severity, cvss_score, status, affected_asset, component, description, remediation, discovered_at)
SELECT * FROM (VALUES
    ('vuln-seed-001', 'CVE-2024-6387', 'OpenSSH regreSSHion — Remote Code Execution', 'critical', 9.8, 'open',
        'bastion-hosts (x4)', 'openssh-server 8.9p1',
        'Signal handler race condition allows unauthenticated remote code execution as root on glibc-based systems.',
        'Upgrade to OpenSSH 9.8 or apply vendor backport patch.', NOW() - INTERVAL '3 days'),
    ('vuln-seed-002', 'CVE-2024-3094', 'XZ Utils Supply-Chain Backdoor', 'critical', 10.0, 'patching',
        'ingest-worker (x6)', 'liblzma 5.6.1',
        'Malicious code injected into the xz build process allows SSH authentication bypass.',
        'Pin liblzma to 5.4.x and rebuild ingest-worker images.', NOW() - INTERVAL '6 days'),
    ('vuln-seed-003', 'CVE-2024-21626', 'runc Container Breakout', 'critical', 8.6, 'patching',
        'k8s-worker-pool', 'runc 1.1.11',
        'File descriptor leak allows a malicious container to access the host filesystem.',
        'Upgrade container runtime to runc 1.1.12+.', NOW() - INTERVAL '4 days'),
    ('vuln-seed-004', 'CVE-2023-44487', 'HTTP/2 Rapid Reset DoS', 'high', 7.5, 'mitigated',
        'api-gateway', 'gin/http2 stack',
        'Rapid stream creation/cancellation can exhaust server resources, causing denial of service.',
        'Stream concurrency limits and connection-level rate limiting deployed at the edge.', NOW() - INTERVAL '12 days'),
    ('vuln-seed-005', NULL, 'Exposed Debug Metrics Endpoint', 'high', 7.2, 'mitigated',
        'monitoring-service', 'internal /metrics route',
        '/metrics endpoint reachable without authentication from the internal network.',
        'Restricted to the monitoring VPC range and added bearer-token auth.', NOW() - INTERVAL '9 days'),
    ('vuln-seed-006', 'CVE-2023-4863', 'libwebp Heap Buffer Overflow', 'high', 8.8, 'resolved',
        'image-thumbnailer', 'libwebp 1.3.1',
        'Crafted WebP images can trigger a heap overflow leading to potential remote code execution.',
        'Upgraded to libwebp 1.3.2 across all document-processing containers.', NOW() - INTERVAL '30 days'),
    ('vuln-seed-007', NULL, 'Weak Password Policy on Service Accounts', 'medium', 6.1, 'accepted_risk',
        'IAM / service accounts', 'auth-service policy config',
        'Legacy service accounts are exempt from the minimum password policy.',
        'Scheduled for rotation to certificate-based auth in Q4 migration.', NOW() - INTERVAL '18 days'),
    ('vuln-seed-008', NULL, 'Outdated TLS Cipher Suite on Legacy Endpoint', 'medium', 5.3, 'open',
        'legacy-report-svc', 'nginx 1.18 TLS config',
        'Endpoint still negotiates TLS 1.1 and CBC cipher suites for backward compatibility.',
        'Consumer notified of TLS 1.3-only cutover date.', NOW() - INTERVAL '5 days')
) AS seed(id, cve_id, title, severity, cvss_score, status, affected_asset, component, description, remediation, discovered_at)
WHERE NOT EXISTS (SELECT 1 FROM vulnerabilities LIMIT 1);

-- Seed blocklist
INSERT INTO blocklist (id, value, type, reason, hit_count, added_by, created_at)
SELECT * FROM (VALUES
    ('blk-seed-001', '185.220.101.4', 'ip', 'Tor exit node — sustained SSH brute-force probing', 214, 'System (auto-rule)', NOW() - INTERVAL '1 day'),
    ('blk-seed-002', 'malicious-c2.ru', 'domain', 'Matches known C2 infrastructure — DNS beacon pattern', 58, 'M. Williams', NOW() - INTERVAL '2 days'),
    ('blk-seed-003', '45.155.205.87', 'ip', 'Ransomware staging host', 6, 'System (auto-rule)', NOW() - INTERVAL '40 minutes'),
    ('blk-seed-004', '91.219.237.19', 'ip', 'Credential stuffing botnet node', 4812, 'S. Chen', NOW() - INTERVAL '3 minutes'),
    ('blk-seed-005', '103.152.36.9', 'ip', 'SQL injection scanner — WAF signature match', 31, 'System (auto-rule)', NOW() - INTERVAL '9 hours')
) AS seed(id, value, type, reason, hit_count, added_by, created_at)
WHERE NOT EXISTS (SELECT 1 FROM blocklist LIMIT 1);
