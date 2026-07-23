package alerts

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

func (s *Service) watchlist() *mongo.Collection { return s.db.Collection("watchlist") }
func (s *Service) rules() *mongo.Collection     { return s.db.Collection("alert_rules") }
func (s *Service) alerts() *mongo.Collection    { return s.db.Collection("alerts") }
func (s *Service) entities() *mongo.Collection  { return s.db.Collection("entities") }

/* -------------------------------- Watchlist ------------------------------- */

func (s *Service) ListWatchlist(ctx context.Context) ([]*WatchlistEntry, error) {
	cur, err := s.watchlist().Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	list := []*WatchlistEntry{}
	if err := cur.All(ctx, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// AddWatchlist adds an entity to the watchlist, resolving its display label
// from the entity's properties at insert time. Dedupes on entity_id: a
// second attempt to watchlist the same entity returns ErrAlreadyWatchlisted
// (surfaced by the handler as 409 Conflict).
func (s *Service) AddWatchlist(ctx context.Context, req AddWatchlistRequest, createdBy string) (*WatchlistEntry, error) {
	var ent struct {
		Properties map[string]interface{} `bson:"properties"`
	}
	if err := s.entities().FindOne(ctx, bson.M{"_id": req.EntityID}).Decode(&ent); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrEntityNotFound
		}
		return nil, err
	}

	label := resolveLabel(ent.Properties)
	if label == "" {
		label = req.EntityID
	}

	entry := &WatchlistEntry{
		ID:          uuid.New().String(),
		EntityID:    req.EntityID,
		EntityLabel: label,
		Note:        req.Note,
		CreatedBy:   createdBy,
		CreatedAt:   time.Now(),
	}
	if _, err := s.watchlist().InsertOne(ctx, entry); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return nil, ErrAlreadyWatchlisted
		}
		return nil, err
	}
	return entry, nil
}

func (s *Service) DeleteWatchlist(ctx context.Context, id string) error {
	res, err := s.watchlist().DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return mongo.ErrNoDocuments
	}
	return nil
}

/* --------------------------------- Alerts --------------------------------- */

// ListAlerts returns a page of alerts, newest first, optionally filtered by
// acknowledged status and/or severity.
func (s *Service) ListAlerts(ctx context.Context, acknowledged *bool, severity string, pg pagination.Params) ([]*Alert, int64, error) {
	filter := bson.M{}
	if acknowledged != nil {
		filter["acknowledged"] = *acknowledged
	}
	if severity != "" {
		filter["severity"] = severity
	}

	total, err := s.alerts().CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetSkip(pg.Skip()).SetLimit(pg.Take())
	cur, err := s.alerts().Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cur.Close(ctx)

	list := []*Alert{}
	if err := cur.All(ctx, &list); err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

// AckAlert acknowledges an alert, recording who and when.
func (s *Service) AckAlert(ctx context.Context, id, ackBy string) (*Alert, error) {
	now := time.Now()
	res, err := s.alerts().UpdateOne(ctx,
		bson.M{"_id": id},
		bson.M{"$set": bson.M{"acknowledged": true, "ack_by": ackBy, "ack_at": now}},
	)
	if err != nil {
		return nil, err
	}
	if res.MatchedCount == 0 {
		return nil, mongo.ErrNoDocuments
	}

	a := &Alert{}
	if err := s.alerts().FindOne(ctx, bson.M{"_id": id}).Decode(a); err != nil {
		return nil, err
	}
	return a, nil
}

/* ------------------------------- Rule CRUD -------------------------------- */

func (s *Service) ListRules(ctx context.Context) ([]*AlertRule, error) {
	cur, err := s.rules().Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	list := []*AlertRule{}
	if err := cur.All(ctx, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s *Service) CreateRule(ctx context.Context, req RuleRequest) (*AlertRule, error) {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	rule := &AlertRule{
		ID:        "rule-" + uuid.New().String()[:8],
		Name:      req.Name,
		Type:      req.Type,
		Enabled:   enabled,
		Severity:  req.Severity,
		Params:    req.Params,
		CreatedAt: time.Now(),
	}
	if rule.Params == nil {
		rule.Params = map[string]interface{}{}
	}
	if _, err := s.rules().InsertOne(ctx, rule); err != nil {
		return nil, err
	}
	return rule, nil
}

func (s *Service) UpdateRule(ctx context.Context, id string, req RuleRequest) (*AlertRule, error) {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	params := req.Params
	if params == nil {
		params = map[string]interface{}{}
	}
	set := bson.M{
		"name":     req.Name,
		"type":     req.Type,
		"enabled":  enabled,
		"severity": req.Severity,
		"params":   params,
	}
	res, err := s.rules().UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": set})
	if err != nil {
		return nil, err
	}
	if res.MatchedCount == 0 {
		return nil, mongo.ErrNoDocuments
	}

	rule := &AlertRule{}
	if err := s.rules().FindOne(ctx, bson.M{"_id": id}).Decode(rule); err != nil {
		return nil, err
	}
	return rule, nil
}

func (s *Service) DeleteRule(ctx context.Context, id string) error {
	res, err := s.rules().DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return mongo.ErrNoDocuments
	}
	return nil
}

// EnsureIndexes creates the unique indexes the watchlist/alerts collections
// rely on: one entity may only appear once on the watchlist, and the
// evaluator's (rule_id, subject_key) upsert dedupe relies on that pair being
// unique. Called from internal/seed on startup.
func EnsureIndexes(ctx context.Context, db *mongo.Database) error {
	if _, err := db.Collection("watchlist").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "entity_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		return err
	}
	if _, err := db.Collection("alerts").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "rule_id", Value: 1}, {Key: "subject_key", Value: 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		return err
	}
	return nil
}
