package events

import (
	"context"
	"time"

	"intelligence-platform/pkg/pagination"

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

func (s *Service) events() *mongo.Collection { return s.db.Collection("events") }

// List returns timeline events ascending by timestamp, optionally filtered by
// event type and/or the entity they belong to. When pg is nil, every match
// is returned (pre-pagination behaviour, total is 0 and should be ignored);
// otherwise a single page plus the total match count is returned.
func (s *Service) List(ctx context.Context, eventType, entityID string, pg *pagination.Params) ([]*Event, int64, error) {
	filter := bson.M{}
	if eventType != "" && eventType != "all" {
		filter["type"] = eventType
	}
	if entityID != "" {
		filter["entity_id"] = entityID
	}

	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}})
	var total int64
	if pg != nil {
		var err error
		total, err = s.events().CountDocuments(ctx, filter)
		if err != nil {
			return nil, 0, err
		}
		opts.SetSkip(pg.Skip()).SetLimit(pg.Take())
	}

	cur, err := s.events().Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cur.Close(ctx)

	list := []*Event{}
	if err := cur.All(ctx, &list); err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

func (s *Service) Create(ctx context.Context, req CreateEventRequest) (*Event, error) {
	e := &Event{
		ID:          uuid.New().String(),
		Timestamp:   req.Timestamp,
		EntityID:    req.EntityID,
		Title:       req.Title,
		Description: req.Description,
		Type:        req.Type,
		Location:    req.Location,
		CreatedAt:   time.Now(),
	}
	if e.Type == "" {
		e.Type = "note"
	}
	if _, err := s.events().InsertOne(ctx, e); err != nil {
		return nil, err
	}
	return e, nil
}
