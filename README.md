# Intelligence Platform — Backend

Go/Gin API backed by **MongoDB Atlas**.

## Setup

### 1. Prerequisites
- Go 1.22+
- A MongoDB database (MongoDB Atlas free tier works)

### 2. Configure
```bash
cp .env.example .env
# edit .env and set MONGO_URI + DB_NAME (and JWT secrets for production)
```

### 3. Install dependencies
```bash
go mod tidy
```

### 4. Run the API
```bash
go run cmd/api/main.go
# or build (this repo needs -buildvcs=false in some environments)
go build -buildvcs=false -o api.exe ./cmd/api && ./api.exe
```

On first start the server auto-creates indexes and seeds users + security demo
data (`internal/seed`). No manual migration step is required.

### Default credentials (seeded)
- **Admin:** admin@platform.io / Admin123!
- **Analyst:** analyst@platform.io / Analyst123!

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/v1/auth/login | Login |
| POST | /api/v1/auth/refresh | Refresh token |
| POST | /api/v1/auth/logout | Logout |
| GET | /api/v1/auth/me | Current user |
| GET | /api/v1/users | List users |
| POST | /api/v1/users | Create user |
| GET | /api/v1/entities | Search entities |
| POST | /api/v1/graph/expand | Graph expand |
| POST | /api/v1/graph/path | Graph path |
| GET | /api/v1/cases | List cases |
| GET | /api/v1/audit | Audit log |
| GET | /api/v1/security/dashboard | Security stats |
| GET | /api/v1/security/incidents | Security incidents |
| GET | /api/v1/security/vulnerabilities | Vulnerabilities |
| GET | /api/v1/security/blocklist | Blocklist |
| GET | /api/v1/security/network-map | Attack map |
| GET | /api/v1/monitoring/metrics | System metrics |
| GET | /api/v1/agents | Remote agents |
| WS | /ws | WebSocket |

## Architecture
- **Framework:** Gin
- **Database:** MongoDB (mongo-driver, `*mongo.Database`)
- **Auth:** JWT (access 15m + refresh 7d); refresh tokens stored in a Mongo
  TTL collection, login lockout is in-memory
- **Real-time:** WebSocket (gorilla/websocket)
- **Logging:** Uber Zap

## Data model (collections)
`users`, `refresh_tokens` (TTL), `audit_logs` (+ `counters`), `entities`,
`relationships`, `cases`, `case_entities`, `security_incidents`,
`vulnerabilities`, `blocklist`, `remote_agents`, `agent_commands`, plus RBAC:
`roles`, `permissions`, `role_permissions`, `user_roles`.
