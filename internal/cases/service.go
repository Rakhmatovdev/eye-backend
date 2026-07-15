package cases

import (
	"context"
	"time"

	"intelligence-platform/internal/entities"

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

func (s *Service) cases() *mongo.Collection        { return s.db.Collection("cases") }
func (s *Service) caseEntities() *mongo.Collection { return s.db.Collection("case_entities") }
func (s *Service) entities() *mongo.Collection     { return s.db.Collection("entities") }

func (s *Service) Create(ctx context.Context, ownerID string, req CreateCaseRequest) (*Case, error) {
	now := time.Now()
	c := &Case{
		ID:             uuid.New().String(),
		Title:          req.Title,
		Description:    req.Description,
		Status:         "open",
		Priority:       req.Priority,
		Classification: req.Classification,
		OwnerID:        ownerID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if _, err := s.cases().InsertOne(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Service) List(ctx context.Context, ownerID string) ([]*Case, error) {
	cur, err := s.cases().Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "updated_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var list []*Case
	if err := cur.All(ctx, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s *Service) Get(ctx context.Context, id string) (*Case, error) {
	c := &Case{}
	if err := s.cases().FindOne(ctx, bson.M{"_id": id}).Decode(c); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Service) AddEntity(ctx context.Context, caseID, entityID, userID string) error {
	filter := bson.M{"case_id": caseID, "entity_id": entityID}
	update := bson.M{"$setOnInsert": bson.M{
		"case_id":    caseID,
		"entity_id":  entityID,
		"added_by":   userID,
		"created_at": time.Now(),
	}}
	_, err := s.caseEntities().UpdateOne(ctx, filter, update, options.Update().SetUpsert(true))
	return err
}

func (s *Service) GetEntities(ctx context.Context, caseID string) ([]*entities.Entity, error) {
	ids, err := s.caseEntities().Distinct(ctx, "entity_id", bson.M{"case_id": caseID})
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return []*entities.Entity{}, nil
	}

	cur, err := s.entities().Find(ctx, bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var list []*entities.Entity
	if err := cur.All(ctx, &list); err != nil {
		return nil, err
	}
	return list, nil
}
