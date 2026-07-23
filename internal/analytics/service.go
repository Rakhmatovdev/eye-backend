package analytics

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// Tunable detector thresholds. Kept as constants (rather than configurable
// rule params, unlike internal/alerts) since patterns are computed fresh on
// every request rather than persisted/configured — see GET /analytics/patterns.
const (
	coLocationWindow    = 30 * time.Minute
	burstMinCount       = 3
	burstMultiplier     = 1.5
	highRiskScoreThresh = 80.0
)

type Service struct {
	db  *mongo.Database
	log *zap.Logger
}

func NewService(db *mongo.Database, log *zap.Logger) *Service {
	return &Service{db: db, log: log}
}

// DetectPatterns runs every detector against live data and returns the
// combined, ID-stamped pattern list. Computed on request — no cron, no ML.
func (s *Service) DetectPatterns(ctx context.Context) ([]Pattern, error) {
	now := time.Now()

	dets, err := s.fetchDetections(ctx)
	if err != nil {
		return nil, err
	}
	rels, err := s.fetchRelationships(ctx)
	if err != nil {
		return nil, err
	}
	ents, err := s.fetchEntities(ctx)
	if err != nil {
		return nil, err
	}
	threats, err := s.fetchThreats(ctx)
	if err != nil {
		return nil, err
	}
	watchlist, err := s.fetchWatchlistSet(ctx)
	if err != nil {
		return nil, err
	}
	events, err := s.fetchEvents(ctx)
	if err != nil {
		return nil, err
	}

	labels := map[string]string{}
	highRisk := map[string]bool{}
	for _, e := range ents {
		labels[e.id] = e.label
		if e.riskScore >= highRiskScoreThresh {
			highRisk[e.id] = true
		}
	}

	degrees := map[string]int{}
	for _, r := range rels {
		degrees[r.from]++
		degrees[r.to]++
	}

	var all []Pattern
	all = append(all, DetectCoLocation(dets, coLocationWindow)...)
	all = append(all, DetectHubEntities(degrees, labels)...)
	all = append(all, DetectThreatCorrelation(threats, watchlist, highRisk, labels)...)

	activity := make([]ActivityRow, 0, len(dets)+len(events))
	for _, d := range dets {
		activity = append(activity, ActivityRow{EntityID: d.EntityID, Timestamp: d.Timestamp})
	}
	for _, e := range events {
		activity = append(activity, ActivityRow{EntityID: e.entityID, Timestamp: e.timestamp})
	}
	all = append(all, DetectBurstActivity(activity, now, burstMinCount, burstMultiplier, labels)...)

	for i := range all {
		all[i].ID = "pat-" + uuid.New().String()[:8]
		all[i].DetectedAt = now
	}
	return all, nil
}

func (s *Service) fetchDetections(ctx context.Context) ([]DetectionRow, error) {
	cur, err := s.db.Collection("detections").Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var rows []struct {
		ID         string    `bson:"_id"`
		SensorID   string    `bson:"sensor_id"`
		EntityID   string    `bson:"entity_id"`
		EntityName string    `bson:"entity_name"`
		Timestamp  time.Time `bson:"timestamp"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]DetectionRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, DetectionRow{ID: r.ID, SensorID: r.SensorID, EntityID: r.EntityID, EntityName: r.EntityName, Timestamp: r.Timestamp})
	}
	return out, nil
}

type relRow struct{ from, to string }

func (s *Service) fetchRelationships(ctx context.Context) ([]relRow, error) {
	cur, err := s.db.Collection("relationships").Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var rows []struct {
		From string `bson:"entity_id_from"`
		To   string `bson:"entity_id_to"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]relRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, relRow{from: r.From, to: r.To})
	}
	return out, nil
}

type entityRow struct {
	id        string
	label     string
	riskScore float64
}

func (s *Service) fetchEntities(ctx context.Context) ([]entityRow, error) {
	cur, err := s.db.Collection("entities").Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var rows []struct {
		ID         string                 `bson:"_id"`
		Properties map[string]interface{} `bson:"properties"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]entityRow, 0, len(rows))
	for _, r := range rows {
		score, _ := toFloat64(r.Properties["risk_score"])
		out = append(out, entityRow{id: r.ID, label: resolveLabel(r.Properties), riskScore: score})
	}
	return out, nil
}

func (s *Service) fetchThreats(ctx context.Context) ([]ThreatRow, error) {
	cur, err := s.db.Collection("mil_threats").Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var rows []struct {
		ID             string `bson:"_id"`
		Designation    string `bson:"designation"`
		Classification string `bson:"classification"`
		EntityID       string `bson:"entity_id"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]ThreatRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, ThreatRow{ID: r.ID, Designation: r.Designation, Classification: r.Classification, EntityID: r.EntityID})
	}
	return out, nil
}

func (s *Service) fetchWatchlistSet(ctx context.Context) (map[string]bool, error) {
	ids, err := s.db.Collection("watchlist").Distinct(ctx, "entity_id", bson.M{})
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		if str, ok := id.(string); ok {
			out[str] = true
		}
	}
	return out, nil
}

type eventRow struct {
	entityID  string
	timestamp time.Time
}

func (s *Service) fetchEvents(ctx context.Context) ([]eventRow, error) {
	cur, err := s.db.Collection("events").Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var rows []struct {
		EntityID  string    `bson:"entity_id"`
		Timestamp time.Time `bson:"timestamp"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]eventRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, eventRow{entityID: r.EntityID, timestamp: r.Timestamp})
	}
	return out, nil
}

// resolveLabel picks a human-readable label from an entity's free-form
// properties map, mirroring internal/alerts' and internal/entities' own
// small helpers of the same shape.
func resolveLabel(props map[string]interface{}) string {
	if props == nil {
		return ""
	}
	if v, ok := props["label"].(string); ok && v != "" {
		return v
	}
	if v, ok := props["name"].(string); ok && v != "" {
		return v
	}
	return ""
}

// toFloat64 coerces a decoded BSON numeric into a float64.
func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}
