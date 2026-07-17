package sensors

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

func (s *Service) sensors() *mongo.Collection    { return s.db.Collection("sensors") }
func (s *Service) detections() *mongo.Collection { return s.db.Collection("detections") }

// List returns sensors, optionally filtered by type and/or status.
func (s *Service) List(ctx context.Context, sensorType, status string) ([]*Sensor, error) {
	filter := bson.M{}
	if sensorType != "" && sensorType != "all" {
		filter["type"] = sensorType
	}
	if status != "" && status != "all" {
		filter["status"] = status
	}
	cur, err := s.sensors().Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "name", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	list := []*Sensor{}
	if err := cur.All(ctx, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s *Service) Get(ctx context.Context, id string) (*Sensor, error) {
	out := &Sensor{}
	if err := s.sensors().FindOne(ctx, bson.M{"_id": id}).Decode(out); err != nil {
		return nil, err
	}
	return out, nil
}

// Detections returns recent detections (newest first), optionally scoped to a
// single sensor or a single entity (used to trace where a person was seen).
func (s *Service) Detections(ctx context.Context, sensorID, entityID string, limit int64) ([]*Detection, error) {
	filter := bson.M{}
	if sensorID != "" {
		filter["sensor_id"] = sensorID
	}
	if entityID != "" {
		filter["entity_id"] = entityID
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	cur, err := s.detections().Find(ctx, filter,
		options.Find().SetSort(bson.D{{Key: "timestamp", Value: -1}}).SetLimit(limit))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	list := []*Detection{}
	if err := cur.All(ctx, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// DetectionsPaginated returns a single page of detections plus the total
// match count, using true page/limit semantics with `meta` in the response.
// It's a separate path from Detections (which keeps its pre-existing
// `?limit=` "simple cap" behaviour used by the live feed) so that existing
// callers passing a bare `?limit=` aren't silently reduced from the old
// 500-item cap down to pagination.MaxLimit — pagination only activates when
// the caller explicitly opts in with `?page=`.
func (s *Service) DetectionsPaginated(ctx context.Context, sensorID, entityID string, pg pagination.Params) ([]*Detection, int64, error) {
	filter := bson.M{}
	if sensorID != "" {
		filter["sensor_id"] = sensorID
	}
	if entityID != "" {
		filter["entity_id"] = entityID
	}

	total, err := s.detections().CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: -1}}).SetSkip(pg.Skip()).SetLimit(pg.Take())
	cur, err := s.detections().Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cur.Close(ctx)

	list := []*Detection{}
	if err := cur.All(ctx, &list); err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

func (s *Service) Create(ctx context.Context, in SensorInput) (*Sensor, error) {
	now := time.Now()
	sen := &Sensor{
		ID:             "sen-" + uuid.New().String()[:8],
		Name:           in.Name,
		Type:           in.Type,
		Status:         orDefault(in.Status, "online"),
		Lat:            in.Lat,
		Lng:            in.Lng,
		Area:           in.Area,
		CoverageRadius: in.CoverageRadius,
		Resolution:     in.Resolution,
		Classification: orDefault(in.Classification, "internal"),
		LastHeartbeat:  now,
		CreatedAt:      now,
	}
	sen.FeedURL = "sim://" + sen.ID
	if _, err := s.sensors().InsertOne(ctx, sen); err != nil {
		return nil, err
	}
	return sen, nil
}

func (s *Service) Update(ctx context.Context, id string, in SensorInput) (*Sensor, error) {
	set := bson.M{
		"name": in.Name, "type": in.Type, "status": orDefault(in.Status, "online"),
		"lat": in.Lat, "lng": in.Lng, "area": in.Area, "coverage_radius": in.CoverageRadius,
		"resolution": in.Resolution, "classification": orDefault(in.Classification, "internal"),
	}
	if _, err := s.sensors().UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": set}); err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

func (s *Service) Delete(ctx context.Context, id string) error {
	_, err := s.sensors().DeleteOne(ctx, bson.M{"_id": id})
	return err
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func (s *Service) Stats(ctx context.Context) (*Stats, error) {
	st := &Stats{}
	st.Total, _ = s.sensors().CountDocuments(ctx, bson.M{})
	st.Online, _ = s.sensors().CountDocuments(ctx, bson.M{"status": "online"})
	st.Degraded, _ = s.sensors().CountDocuments(ctx, bson.M{"status": "degraded"})
	st.Offline, _ = s.sensors().CountDocuments(ctx, bson.M{"status": "offline"})
	since := time.Now().Add(-24 * time.Hour)
	st.Detections24h, _ = s.detections().CountDocuments(ctx, bson.M{"timestamp": bson.M{"$gte": since}})
	st.IdentifiedHits, _ = s.detections().CountDocuments(ctx, bson.M{"entity_id": bson.M{"$ne": ""}})
	return st, nil
}
