# Intelligence Platform — Backend

## Setup Instructions

### 1. Prerequisites
- Go 1.22+
- Docker & Docker Compose

### 2. Start Infrastructure
```bash
cp .env.example .env
docker-compose up -d
```

### 3. Install Dependencies
```bash
go mod tidy
```

### 4. Apply Database Migrations
Run each migration file against the `intelligence_db` database, in order (there is no
auto-migrate step in `cmd/api`):
```bash
docker exec -i $(docker compose ps -q postgres) psql -U intel_user -d intelligence_db < migrations/001_init.sql
docker exec -i $(docker compose ps -q postgres) psql -U intel_user -d intelligence_db < migrations/002_security_enhancements.sql
```

### 5. Run the API
```bash
go run cmd/api/main.go
```

### 5. Default Admin Credentials
- **Email:** admin@platform.io
- **Password:** Admin123!

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
| GET | /api/v1/monitoring/metrics | System metrics |
| GET | /api/v1/agents | Remote agents |
| WS | /ws | Main WebSocket |
| WS | /ws/monitoring | Monitoring stream |
| WS | /ws/agents | Agent stream |

## Architecture
- **Framework:** Gin
- **Database:** PostgreSQL 16 (pgx/v5)
- **Cache/Sessions:** Redis 7
- **Auth:** JWT (access 15m + refresh 7d)
- **Real-time:** WebSocket (gorilla/websocket)
- **Logging:** Uber Zap
