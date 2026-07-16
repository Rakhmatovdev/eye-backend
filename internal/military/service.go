package military

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

func (s *Service) units() *mongo.Collection    { return s.db.Collection("mil_units") }
func (s *Service) threats() *mongo.Collection  { return s.db.Collection("mil_threats") }
func (s *Service) missions() *mongo.Collection { return s.db.Collection("mil_missions") }

func (s *Service) Units(ctx context.Context) ([]*Unit, error) {
	cur, err := s.units().Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "callsign", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	out := []*Unit{}
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Threats returns tracks, newest sighting first, optionally filtered by class.
func (s *Service) Threats(ctx context.Context, classification string) ([]*Threat, error) {
	filter := bson.M{}
	if classification != "" && classification != "all" {
		filter["classification"] = classification
	}
	cur, err := s.threats().Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "last_seen", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	out := []*Threat{}
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) Missions(ctx context.Context) ([]*Mission, error) {
	cur, err := s.missions().Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "starts_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	out := []*Mission{}
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

/* ------------------------------ Unit CRUD -------------------------------- */

func (s *Service) CreateUnit(ctx context.Context, u *Unit) (*Unit, error) {
	u.ID = "u-" + uuid.New().String()[:8]
	u.UpdatedAt = time.Now()
	if _, err := s.units().InsertOne(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}
func (s *Service) UpdateUnit(ctx context.Context, id string, u *Unit) (*Unit, error) {
	u.ID = id
	u.UpdatedAt = time.Now()
	if _, err := s.units().ReplaceOne(ctx, bson.M{"_id": id}, u); err != nil {
		return nil, err
	}
	return u, nil
}
func (s *Service) DeleteUnit(ctx context.Context, id string) error {
	_, err := s.units().DeleteOne(ctx, bson.M{"_id": id})
	return err
}

/* ----------------------------- Threat CRUD ------------------------------- */

func (s *Service) CreateThreat(ctx context.Context, t *Threat) (*Threat, error) {
	t.ID = "t-" + uuid.New().String()[:8]
	t.LastSeen = time.Now()
	if _, err := s.threats().InsertOne(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}
func (s *Service) UpdateThreat(ctx context.Context, id string, t *Threat) (*Threat, error) {
	t.ID = id
	t.LastSeen = time.Now()
	if _, err := s.threats().ReplaceOne(ctx, bson.M{"_id": id}, t); err != nil {
		return nil, err
	}
	return t, nil
}
func (s *Service) DeleteThreat(ctx context.Context, id string) error {
	_, err := s.threats().DeleteOne(ctx, bson.M{"_id": id})
	return err
}

/* ---------------------------- Mission CRUD ------------------------------- */

func (s *Service) CreateMission(ctx context.Context, m *Mission) (*Mission, error) {
	m.ID = "m-" + uuid.New().String()[:8]
	now := time.Now()
	if m.StartsAt.IsZero() {
		m.StartsAt = now
	}
	m.UpdatedAt = now
	if m.AssignedUnits == nil {
		m.AssignedUnits = []string{}
	}
	if _, err := s.missions().InsertOne(ctx, m); err != nil {
		return nil, err
	}
	return m, nil
}
func (s *Service) UpdateMission(ctx context.Context, id string, m *Mission) (*Mission, error) {
	m.ID = id
	m.UpdatedAt = time.Now()
	if m.AssignedUnits == nil {
		m.AssignedUnits = []string{}
	}
	if _, err := s.missions().ReplaceOne(ctx, bson.M{"_id": id}, m); err != nil {
		return nil, err
	}
	return m, nil
}
func (s *Service) DeleteMission(ctx context.Context, id string) error {
	_, err := s.missions().DeleteOne(ctx, bson.M{"_id": id})
	return err
}

func (s *Service) Stats(ctx context.Context) (*Stats, error) {
	st := &Stats{}
	st.Units, _ = s.units().CountDocuments(ctx, bson.M{})
	st.UnitsReady, _ = s.units().CountDocuments(ctx, bson.M{"readiness": "green"})
	st.Threats, _ = s.threats().CountDocuments(ctx, bson.M{})
	st.CriticalThreats, _ = s.threats().CountDocuments(ctx, bson.M{"threat_level": "critical"})
	st.ActiveMissions, _ = s.missions().CountDocuments(ctx, bson.M{"status": "active"})
	return st, nil
}
