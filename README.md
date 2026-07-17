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
| GET | /health | Public health probe: `{status, db, uptime_seconds}` (503 if DB down) |
| POST | /api/v1/auth/login | Login |
| POST | /api/v1/auth/refresh | Refresh token |
| POST | /api/v1/auth/logout | Logout |
| GET | /api/v1/auth/me | Current user |
| POST | /api/v1/auth/change-password | Change own password; revokes refresh tokens |
| GET | /api/v1/users | List users (`?page=&limit=`) |
| POST | /api/v1/users | Create user |
| GET | /api/v1/entities | Search entities (`?page=&limit=`) |
| PUT | /api/v1/entities/:id | Partial update (type/label/properties/classification) |
| DELETE | /api/v1/entities/:id | Delete entity + its relationships + case_items |
| DELETE | /api/v1/entities/relationship/:id | Delete a relationship |
| POST | /api/v1/graph/expand | Graph expand |
| POST | /api/v1/graph/path | Graph path |
| GET | /api/v1/cases | List cases |
| PATCH | /api/v1/cases/:id | Update title/description/status |
| DELETE | /api/v1/cases/:id | Delete case + its case_items |
| DELETE | /api/v1/cases/:id/entities/:entity_id | Remove one entity from a case |
| GET | /api/v1/audit | Audit log (`?page=&limit=`) |
| GET | /api/v1/security/dashboard | Security stats |
| GET | /api/v1/security/incidents | Security incidents (`?page=&limit=`) |
| GET | /api/v1/security/vulnerabilities | Vulnerabilities |
| GET | /api/v1/security/blocklist | Blocklist |
| GET | /api/v1/security/network-map | Attack map |
| GET | /api/v1/monitoring/metrics | System metrics |
| GET | /api/v1/agents | Remote agents |
| POST | /api/v1/ai/chat | AI analyst chat (persists exchange to `ai_chats`) |
| GET | /api/v1/ai/history | Current user's recent chat exchanges, oldest-first |
| WS | /ws?token=&lt;access_token&gt; | WebSocket (JWT required as query param) |

List endpoints marked `?page=&limit=` (`/entities`, `/users`, `/audit`,
`/security/incidents`, `/timeline`, `/sensors/detections`) accept optional
pagination; when both params are omitted they return every match with no
`meta`, exactly as before. When either is present the response includes
`meta {page, limit, total}`.

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
`vulnerabilities`, `blocklist`, `remote_agents`, `agent_commands`, `ai_chats`,
plus RBAC: `roles`, `permissions`, `role_permissions`, `user_roles`.

## Docker
```bash
docker build -t koz-backend .
docker run --rm -p 8080:8080 --env-file .env koz-backend
```
Multi-stage build: `golang:1.22` compiles a static binary
(`go build -buildvcs=false -o /app ./cmd/api`), then a `distroless` runtime
image serves it on port 8080.

## CI
`.github/workflows/ci.yml` runs on every push/PR to `main`: Go 1.22 setup,
`go build -buildvcs=false ./...`, `go vet ./...`, `go test ./...`.
