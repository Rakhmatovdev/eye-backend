package alerts

import (
	"context"
	"fmt"
	"strings"
	"time"

	"intelligence-platform/internal/realtime"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// EvaluatorInterval is how often the background evaluator re-checks enabled
// rules against live data.
const EvaluatorInterval = 30 * time.Second

/* ------------------------------ pure logic -------------------------------
   Everything in this block is a pure function over already-fetched Go
   values: no *mongo.Database, no I/O. This is what evaluator_test.go
   exercises directly, matching the DB-free unit test style used elsewhere
   in this codebase (e.g. internal/accesscontrol/middleware_test.go). */

// Candidate is a pending alert produced by rule evaluation, before dedupe and
// insertion. Exactly one of EntityID/ThreatID/DetectionID identifies the
// primary subject the alert is about (EntityID may additionally be set
// alongside ThreatID for a threat_class match linked to an entity).
type Candidate struct {
	EntityID    string
	ThreatID    string
	DetectionID string
	Title       string
	Message     string
}

// DedupeKey returns the stable key identifying a (rule, subject) pair. The
// evaluator upserts on (rule_id, subject_key) so the same subject never
// re-alerts on every tick — only once per rule, ever (until the alert or
// underlying data is removed).
func DedupeKey(ruleID string, c Candidate) string {
	switch {
	case c.DetectionID != "":
		return ruleID + "|detection|" + c.DetectionID
	case c.ThreatID != "":
		return ruleID + "|threat|" + c.ThreatID
	case c.EntityID != "":
		return ruleID + "|entity|" + c.EntityID
	default:
		return ruleID + "|unknown"
	}
}

// DetectionInput is the subset of a sensors.Detection the watchlist_detection
// rule needs. Duplicated here (rather than importing internal/sensors) to
// keep this package dependency-free of sibling domain packages, matching the
// pattern already used by internal/ai's grounding queries.
type DetectionInput struct {
	ID         string
	EntityID   string
	EntityName string
}

// EvaluateWatchlistDetection returns one Candidate per detection whose
// entity_id is present in the watchlist set.
func EvaluateWatchlistDetection(detections []DetectionInput, watchlist map[string]bool) []Candidate {
	var out []Candidate
	for _, d := range detections {
		if d.EntityID == "" || !watchlist[d.EntityID] {
			continue
		}
		name := d.EntityName
		if name == "" {
			name = d.EntityID
		}
		out = append(out, Candidate{
			EntityID:    d.EntityID,
			DetectionID: d.ID,
			Title:       "Watchlisted entity detected",
			Message:     fmt.Sprintf("%s, who is on the watchlist, was picked up by a sensor.", name),
		})
	}
	return out
}

// ThreatInput is the subset of a military.Threat the threat_class rule needs.
type ThreatInput struct {
	ID             string
	Designation    string
	Classification string
	EntityID       string
}

// EvaluateThreatClass returns one Candidate per threat whose classification
// is in the rule's watched class set (case-insensitive).
func EvaluateThreatClass(threats []ThreatInput, classes []string) []Candidate {
	classSet := map[string]bool{}
	for _, c := range classes {
		classSet[strings.ToLower(strings.TrimSpace(c))] = true
	}
	var out []Candidate
	for _, t := range threats {
		if !classSet[strings.ToLower(t.Classification)] {
			continue
		}
		out = append(out, Candidate{
			ThreatID: t.ID,
			EntityID: t.EntityID,
			Title:    "Threat classification match",
			Message:  fmt.Sprintf("Track %s is classified %q, matching this rule's watched classes.", t.Designation, t.Classification),
		})
	}
	return out
}

// EntityInput is the subset of an entities.Entity the risk_threshold rule
// needs.
type EntityInput struct {
	ID        string
	Label     string
	RiskScore float64
	HasScore  bool
}

// EvaluateRiskThreshold returns one Candidate per entity whose risk score is
// present and >= minScore.
func EvaluateRiskThreshold(ents []EntityInput, minScore float64) []Candidate {
	var out []Candidate
	for _, e := range ents {
		if !e.HasScore || e.RiskScore < minScore {
			continue
		}
		label := e.Label
		if label == "" {
			label = e.ID
		}
		out = append(out, Candidate{
			EntityID: e.ID,
			Title:    "High risk entity",
			Message:  fmt.Sprintf("%s has a risk score of %.0f, at or above the rule threshold of %.0f.", label, e.RiskScore, minScore),
		})
	}
	return out
}

/* --------------------------- background evaluator ------------------------- */

// StartEvaluator runs the rule-evaluation loop forever. Call once, in a
// goroutine, from cmd/api/main.go (mirrors realtime.StartBroadcaster /
// monitoring.StartSampler). It evaluates once immediately, then every
// EvaluatorInterval, so seed rules produce alerts on first run instead of
// waiting a full tick.
func StartEvaluator(db *mongo.Database, hub *realtime.Hub, log *zap.Logger) {
	ticker := time.NewTicker(EvaluatorInterval)
	defer ticker.Stop()

	runEvaluation(db, hub, log)
	for range ticker.C {
		runEvaluation(db, hub, log)
	}
}

func runEvaluation(db *mongo.Database, hub *realtime.Hub, log *zap.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cur, err := db.Collection("alert_rules").Find(ctx, bson.M{"enabled": true})
	if err != nil {
		log.Error("alerts: failed to load rules", zap.Error(err))
		return
	}
	var rules []AlertRule
	if err := cur.All(ctx, &rules); err != nil {
		log.Error("alerts: failed to decode rules", zap.Error(err))
		return
	}

	for _, rule := range rules {
		var candidates []Candidate
		switch rule.Type {
		case "watchlist_detection":
			candidates = evalWatchlistDetectionRule(ctx, db, log)
		case "threat_class":
			candidates = evalThreatClassRule(ctx, db, rule.Params, log)
		case "risk_threshold":
			candidates = evalRiskThresholdRule(ctx, db, rule.Params, log)
		default:
			continue
		}
		for _, cand := range candidates {
			insertIfNew(ctx, db, hub, log, rule, cand)
		}
	}
}

func insertIfNew(ctx context.Context, db *mongo.Database, hub *realtime.Hub, log *zap.Logger, rule AlertRule, cand Candidate) {
	key := DedupeKey(rule.ID, cand)
	doc := Alert{
		ID:          uuid.New().String(),
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		Severity:    rule.Severity,
		Title:       cand.Title,
		Message:     cand.Message,
		EntityID:    cand.EntityID,
		ThreatID:    cand.ThreatID,
		DetectionID: cand.DetectionID,
		SubjectKey:  key,
		CreatedAt:   time.Now(),
	}

	res, err := db.Collection("alerts").UpdateOne(ctx,
		bson.M{"rule_id": rule.ID, "subject_key": key},
		bson.M{"$setOnInsert": doc},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		log.Error("alerts: upsert failed", zap.Error(err), zap.String("rule_id", rule.ID))
		return
	}
	if res.UpsertedCount == 0 {
		return // already alerted for this (rule, subject) — deduped
	}

	log.Info("alerts: new alert", zap.String("rule", rule.Name), zap.String("subject_key", key))
	if hub != nil {
		hub.BroadcastMessage(map[string]interface{}{"type": "alert", "data": doc})
	}
}

func evalWatchlistDetectionRule(ctx context.Context, db *mongo.Database, log *zap.Logger) []Candidate {
	watchlist, err := fetchWatchlistSet(ctx, db)
	if err != nil {
		log.Error("alerts: failed to load watchlist", zap.Error(err))
		return nil
	}
	if len(watchlist) == 0 {
		return nil
	}

	ids := make([]string, 0, len(watchlist))
	for id := range watchlist {
		ids = append(ids, id)
	}

	cur, err := db.Collection("detections").Find(ctx, bson.M{"entity_id": bson.M{"$in": ids}})
	if err != nil {
		log.Error("alerts: failed to query detections", zap.Error(err))
		return nil
	}
	defer cur.Close(ctx)

	var rows []struct {
		ID         string `bson:"_id"`
		EntityID   string `bson:"entity_id"`
		EntityName string `bson:"entity_name"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		log.Error("alerts: failed to decode detections", zap.Error(err))
		return nil
	}

	inputs := make([]DetectionInput, 0, len(rows))
	for _, r := range rows {
		inputs = append(inputs, DetectionInput{ID: r.ID, EntityID: r.EntityID, EntityName: r.EntityName})
	}
	return EvaluateWatchlistDetection(inputs, watchlist)
}

func evalThreatClassRule(ctx context.Context, db *mongo.Database, params map[string]interface{}, log *zap.Logger) []Candidate {
	classes := toStringSlice(params["classes"])
	if len(classes) == 0 {
		return nil
	}

	cur, err := db.Collection("mil_threats").Find(ctx, bson.M{})
	if err != nil {
		log.Error("alerts: failed to query threats", zap.Error(err))
		return nil
	}
	defer cur.Close(ctx)

	var rows []struct {
		ID             string `bson:"_id"`
		Designation    string `bson:"designation"`
		Classification string `bson:"classification"`
		EntityID       string `bson:"entity_id"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		log.Error("alerts: failed to decode threats", zap.Error(err))
		return nil
	}

	inputs := make([]ThreatInput, 0, len(rows))
	for _, r := range rows {
		inputs = append(inputs, ThreatInput{ID: r.ID, Designation: r.Designation, Classification: r.Classification, EntityID: r.EntityID})
	}
	return EvaluateThreatClass(inputs, classes)
}

func evalRiskThresholdRule(ctx context.Context, db *mongo.Database, params map[string]interface{}, log *zap.Logger) []Candidate {
	minScore, ok := toFloat64(params["min_score"])
	if !ok {
		return nil
	}

	cur, err := db.Collection("entities").Find(ctx, bson.M{})
	if err != nil {
		log.Error("alerts: failed to query entities", zap.Error(err))
		return nil
	}
	defer cur.Close(ctx)

	var rows []struct {
		ID         string                 `bson:"_id"`
		Properties map[string]interface{} `bson:"properties"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		log.Error("alerts: failed to decode entities", zap.Error(err))
		return nil
	}

	inputs := make([]EntityInput, 0, len(rows))
	for _, r := range rows {
		score, hasScore := toFloat64(r.Properties["risk_score"])
		inputs = append(inputs, EntityInput{ID: r.ID, Label: resolveLabel(r.Properties), RiskScore: score, HasScore: hasScore})
	}
	return EvaluateRiskThreshold(inputs, minScore)
}

func fetchWatchlistSet(ctx context.Context, db *mongo.Database) (map[string]bool, error) {
	ids, err := db.Collection("watchlist").Distinct(ctx, "entity_id", bson.M{})
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		if s, ok := id.(string); ok {
			out[s] = true
		}
	}
	return out, nil
}
