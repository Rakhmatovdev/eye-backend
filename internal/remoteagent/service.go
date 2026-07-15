package remoteagent

import (
	"context"

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

func (s *Service) ListAgents(ctx context.Context) ([]*RemoteAgent, error) {
	rows, err := s.db.Query(ctx, "SELECT id, name, status, version, last_heartbeat, public_key, created_at FROM remote_agents ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*RemoteAgent
	for rows.Next() {
		a := &RemoteAgent{}
		err = rows.Scan(&a.ID, &a.Name, &a.Status, &a.Version, &a.LastHeartbeat, &a.PublicKey, &a.CreatedAt)
		if err != nil {
			return nil, err
		}
		list = append(list, a)
	}
	return list, nil
}

func (s *Service) GetAgent(ctx context.Context, id string) (*RemoteAgent, error) {
	a := &RemoteAgent{}
	err := s.db.QueryRow(ctx,
		`SELECT id, name, status, version, last_heartbeat, public_key, created_at 
		 FROM remote_agents WHERE id = $1`, id,
	).Scan(&a.ID, &a.Name, &a.Status, &a.Version, &a.LastHeartbeat, &a.PublicKey, &a.CreatedAt)
	return a, err
}

func (s *Service) CreateCommand(ctx context.Context, agentID, command, userID string) (*AgentCommand, error) {
	id := uuid.New().String()
	c := &AgentCommand{}
	err := s.db.QueryRow(ctx,
		`INSERT INTO agent_commands (id, agent_id, command, status, issued_by)
		 VALUES ($1, $2, $3, 'pending', $4)
		 RETURNING id, agent_id, command, status, issued_by, created_at, updated_at`,
		id, agentID, command, userID,
	).Scan(&c.ID, &c.AgentID, &c.Command, &c.Status, &c.IssuedBy, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func (s *Service) ListCommands(ctx context.Context, agentID string) ([]*AgentCommand, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, agent_id, command, status, issued_by, created_at, updated_at 
		 FROM agent_commands WHERE agent_id = $1 ORDER BY created_at DESC LIMIT 50`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*AgentCommand
	for rows.Next() {
		c := &AgentCommand{}
		err = rows.Scan(&c.ID, &c.AgentID, &c.Command, &c.Status, &c.IssuedBy, &c.CreatedAt, &c.UpdatedAt)
		if err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, nil
}
