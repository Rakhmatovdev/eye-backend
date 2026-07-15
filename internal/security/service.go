package security

import (
	"context"
	"strings"
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

func (s *Service) incidents() *mongo.Collection { return s.db.Collection("security_incidents") }
func (s *Service) blocklist() *mongo.Collection { return s.db.Collection("blocklist") }
func (s *Service) vulns() *mongo.Collection      { return s.db.Collection("vulnerabilities") }

func (s *Service) GetDashboardStats(ctx context.Context) (map[string]interface{}, error) {
	criticalOpen, _ := s.incidents().CountDocuments(ctx, bson.M{"severity": "critical", "status": bson.M{"$ne": "resolved"}})
	highOpen, _ := s.incidents().CountDocuments(ctx, bson.M{"severity": "high", "status": bson.M{"$ne": "resolved"}})
	totalOpen, _ := s.incidents().CountDocuments(ctx, bson.M{"status": bson.M{"$ne": "resolved"}})
	blockedCount, _ := s.blocklist().CountDocuments(ctx, bson.M{})
	openVulns, _ := s.vulns().CountDocuments(ctx, bson.M{"status": bson.M{"$in": bson.A{"open", "patching"}}})
	criticalVulns, _ := s.vulns().CountDocuments(ctx, bson.M{"severity": "critical", "status": bson.M{"$nin": bson.A{"resolved"}}})

	riskScore := 12 + int(criticalOpen)*16 + int(highOpen)*7 + int(openVulns)*3 + int(criticalVulns)*6
	if riskScore > 100 {
		riskScore = 100
	}

	return map[string]interface{}{
		"critical_incidents":   int(criticalOpen),
		"high_incidents":       int(highOpen),
		"open_threats":         int(totalOpen),
		"blocked_items":        int(blockedCount),
		"open_vulnerabilities": int(openVulns),
		"overall_risk_score":   riskScore,
	}, nil
}

func (s *Service) ListIncidents(ctx context.Context) ([]*SecurityIncident, error) {
	opts := options.Find().SetSort(bson.D{{Key: "ts", Value: -1}}).SetLimit(200)
	cur, err := s.incidents().Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var list []*SecurityIncident
	if err := cur.All(ctx, &list); err != nil {
		return nil, err
	}
	for _, si := range list {
		if si.AffectedAssets == nil {
			si.AffectedAssets = []string{}
		}
	}
	return list, nil
}

func (s *Service) GetIncident(ctx context.Context, id string) (*SecurityIncident, error) {
	si := &SecurityIncident{}
	if err := s.incidents().FindOne(ctx, bson.M{"_id": id}).Decode(si); err != nil {
		return nil, err
	}
	if si.AffectedAssets == nil {
		si.AffectedAssets = []string{}
	}
	return si, nil
}

func (s *Service) UpdateIncidentStatus(ctx context.Context, id, status string) error {
	_, err := s.incidents().UpdateByID(ctx, id, bson.M{"$set": bson.M{"status": status}})
	return err
}

func (s *Service) ResolveIncident(ctx context.Context, id string) error {
	return s.UpdateIncidentStatus(ctx, id, "resolved")
}

func (s *Service) AssignIncident(ctx context.Context, id, assignee string) error {
	_, err := s.incidents().UpdateByID(ctx, id, bson.M{"$set": bson.M{"assignee": assignee}})
	return err
}

func (s *Service) AddToBlocklist(ctx context.Context, req CreateBlocklistRequest, addedBy string) (*BlocklistItem, error) {
	if addedBy == "" {
		addedBy = "Admin"
	}
	item := &BlocklistItem{
		ID:        uuid.New().String(),
		Value:     req.Value,
		Type:      req.Type,
		Reason:    req.Reason,
		HitCount:  0,
		AddedBy:   addedBy,
		CreatedAt: time.Now(),
	}
	if _, err := s.blocklist().InsertOne(ctx, item); err != nil {
		return nil, err
	}
	return item, nil
}

func (s *Service) ListBlocklist(ctx context.Context) ([]*BlocklistItem, error) {
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cur, err := s.blocklist().Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var list []*BlocklistItem
	if err := cur.All(ctx, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s *Service) RemoveFromBlocklist(ctx context.Context, id string) error {
	_, err := s.blocklist().DeleteOne(ctx, bson.M{"_id": id})
	return err
}

func (s *Service) ListVulnerabilities(ctx context.Context) ([]*Vulnerability, error) {
	opts := options.Find().SetSort(bson.D{{Key: "cvss_score", Value: -1}})
	cur, err := s.vulns().Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var list []*Vulnerability
	if err := cur.All(ctx, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s *Service) UpdateVulnerabilityStatus(ctx context.Context, id, status string) (*Vulnerability, error) {
	_, err := s.vulns().UpdateByID(ctx, id, bson.M{"$set": bson.M{"status": status, "updated_at": time.Now()}})
	if err != nil {
		return nil, err
	}
	v := &Vulnerability{}
	if err := s.vulns().FindOne(ctx, bson.M{"_id": id}).Decode(v); err != nil {
		return nil, err
	}
	return v, nil
}

func (s *Service) GetAttackMap(ctx context.Context) ([]*AttackMapNode, error) {
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{
			"source_ip": bson.M{"$nin": bson.A{nil, "", "unknown"}},
		}}},
		{{Key: "$group", Value: bson.M{
			"_id":        "$source_ip",
			"cnt":        bson.M{"$sum": 1},
			"severities": bson.M{"$push": "$severity"},
		}}},
		{{Key: "$sort", Value: bson.M{"cnt": -1}}},
		{{Key: "$limit", Value: 9}},
	}

	cur, err := s.incidents().Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var rows []struct {
		IP         string   `bson:"_id"`
		Count      int      `bson:"cnt"`
		Severities []string `bson:"severities"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}

	var nodes []*AttackMapNode
	for _, r := range rows {
		kind := "ip"
		if strings.HasPrefix(r.IP, "10.") || strings.HasPrefix(r.IP, "172.16.") {
			kind = "asset"
		}
		nodes = append(nodes, &AttackMapNode{
			ID:            r.IP,
			Label:         r.IP,
			Kind:          kind,
			IncidentCount: r.Count,
			Severity:      topSeverity(r.Severities),
		})
	}
	return nodes, nil
}

// topSeverity returns the highest-ranked severity from a list.
func topSeverity(severities []string) string {
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	best := ""
	bestRank := 0
	for _, sev := range severities {
		if rank[sev] > bestRank {
			bestRank = rank[sev]
			best = sev
		}
	}
	return best
}
