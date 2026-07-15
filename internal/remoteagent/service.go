package remoteagent

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

type Service struct {
	db  *mongo.Database
	log *zap.Logger
}

func NewService(db *mongo.Database, log *zap.Logger) *Service {
	return &Service{db: db, log: log}
}

func (s *Service) agents() *mongo.Collection   { return s.db.Collection("remote_agents") }
func (s *Service) commands() *mongo.Collection { return s.db.Collection("agent_commands") }

func (s *Service) ListAgents(ctx context.Context) ([]*RemoteAgent, error) {
	cur, err := s.agents().Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "name", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var list []*RemoteAgent
	if err := cur.All(ctx, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s *Service) GetAgent(ctx context.Context, id string) (*RemoteAgent, error) {
	a := &RemoteAgent{}
	if err := s.agents().FindOne(ctx, bson.M{"_id": id}).Decode(a); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Service) CreateCommand(ctx context.Context, agentID, command, userID string) (*AgentCommand, error) {
	now := time.Now()
	c := &AgentCommand{
		ID:        uuid.New().String(),
		AgentID:   agentID,
		Command:   command,
		Status:    "pending",
		IssuedBy:  userID,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if _, err := s.commands().InsertOne(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Service) ListCommands(ctx context.Context, agentID string) ([]*AgentCommand, error) {
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(50)
	cur, err := s.commands().Find(ctx, bson.M{"agent_id": agentID}, opts)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var list []*AgentCommand
	if err := cur.All(ctx, &list); err != nil {
		return nil, err
	}
	return list, nil
}
