-- 001_init.sql
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL,
    clearance_level INT NOT NULL DEFAULT 1,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    department VARCHAR(100) NOT NULL DEFAULT 'General',
    last_login TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(36),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    result VARCHAR(50) NOT NULL,
    hash VARCHAR(64) NOT NULL,
    prev_hash VARCHAR(64) NOT NULL,
    ts TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS entities (
    id VARCHAR(36) PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    properties JSONB NOT NULL DEFAULT '{}',
    classification VARCHAR(50) NOT NULL DEFAULT 'internal',
    source_id VARCHAR(100),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS relationships (
    id VARCHAR(36) PRIMARY KEY,
    entity_id_from VARCHAR(36) NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    entity_id_to VARCHAR(36) NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    properties JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cases (
    id VARCHAR(36) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    priority VARCHAR(50) NOT NULL DEFAULT 'medium',
    classification VARCHAR(50) NOT NULL DEFAULT 'internal',
    owner_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS case_entities (
    case_id VARCHAR(36) REFERENCES cases(id) ON DELETE CASCADE,
    entity_id VARCHAR(36) REFERENCES entities(id) ON DELETE CASCADE,
    added_by VARCHAR(36) REFERENCES users(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (case_id, entity_id)
);

CREATE TABLE IF NOT EXISTS security_incidents (
    id VARCHAR(36) PRIMARY KEY,
    type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    risk_score INT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    details JSONB NOT NULL DEFAULT '{}',
    ts TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS remote_agents (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'offline',
    version VARCHAR(50) NOT NULL,
    last_heartbeat TIMESTAMP,
    public_key TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_commands (
    id VARCHAR(36) PRIMARY KEY,
    agent_id VARCHAR(36) REFERENCES remote_agents(id) ON DELETE CASCADE,
    command VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    issued_by VARCHAR(36) REFERENCES users(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS blocklist (
    id VARCHAR(36) PRIMARY KEY,
    value VARCHAR(255) UNIQUE NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'ip' or 'domain'
    reason TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Seed basic roles and admin user
-- Admin password is "Admin123!" hashed with bcrypt
INSERT INTO users (id, email, password_hash, first_name, last_name, role, clearance_level, status, department)
VALUES (
    'admin-uuid-0000-0000-000000000000',
    'admin@platform.io',
    '$2a$10$VdDVxwB2jySPmWJk96fUMeMkGoM/ARvM9vrQ/o3IgFBlAnpQG/1Om', -- bcrypt for 'Admin123!'
    'System',
    'Administrator',
    'admin',
    5,
    'active',
    'Security'
) ON CONFLICT (email) DO NOTHING;

-- Seed Analyst user (Analyst123!)
INSERT INTO users (id, email, password_hash, first_name, last_name, role, clearance_level, status, department)
VALUES (
    'analyst-uuid-0000-0000-000000000000',
    'analyst@platform.io',
    '$2a$10$D.LFcdoEMNzaHLYVsbwakuDlwWit1nZuWvgtqc2hWleGZdbaom/O6', -- bcrypt for 'Analyst123!'
    'John',
    'Analyst',
    'analyst',
    3,
    'active',
    'Intelligence'
) ON CONFLICT (email) DO NOTHING;
