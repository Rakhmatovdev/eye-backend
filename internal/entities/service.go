package entities

import (
	"context"
	"fmt"
	"strings"
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

func (s *Service) entities() *mongo.Collection      { return s.db.Collection("entities") }
func (s *Service) relationships() *mongo.Collection { return s.db.Collection("relationships") }
func (s *Service) caseEntities() *mongo.Collection  { return s.db.Collection("case_entities") }

func (s *Service) CreateEntity(ctx context.Context, req CreateEntityRequest) (*Entity, error) {
	now := time.Now()
	e := &Entity{
		ID:             uuid.New().String(),
		Type:           req.Type,
		Properties:     req.Properties,
		Classification: req.Classification,
		SourceID:       req.SourceID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if e.Properties == nil {
		e.Properties = map[string]interface{}{}
	}
	if _, err := s.entities().InsertOne(ctx, e); err != nil {
		return nil, err
	}
	return e, nil
}

func (s *Service) GetEntity(ctx context.Context, id string) (*Entity, error) {
	e := &Entity{}
	if err := s.entities().FindOne(ctx, bson.M{"_id": id}).Decode(e); err != nil {
		return nil, err
	}
	return e, nil
}

// ListEntities returns entities matching the optional search/type filters. If
// pg is nil, pagination is not applied and every matching entity is returned
// (preserves pre-pagination behaviour for callers that don't send
// ?page=/&limit=). The returned int64 is the total match count (0 when pg is
// nil, since callers that skip pagination don't need it).
func (s *Service) ListEntities(ctx context.Context, search, entType string, pg *pagination.Params) ([]*Entity, int64, error) {
	filter := bson.M{}
	if entType != "" {
		filter["type"] = entType
	}

	// Free-form property search is done in-application (mirrors the old
	// `properties::text ILIKE` behaviour across arbitrary JSON values), so it
	// can't be combined with a Mongo-level skip/limit. Paginate in memory
	// instead when a search term is present.
	if search != "" {
		cur, err := s.entities().Find(ctx, filter)
		if err != nil {
			return nil, 0, err
		}
		defer cur.Close(ctx)

		var all []*Entity
		if err := cur.All(ctx, &all); err != nil {
			return nil, 0, err
		}

		needle := strings.ToLower(search)
		var matched []*Entity
		for _, e := range all {
			if entityMatches(e, needle) {
				matched = append(matched, e)
			}
		}
		total := int64(len(matched))
		if pg == nil {
			return matched, total, nil
		}
		start := pg.Skip()
		if start > total {
			start = total
		}
		end := start + pg.Take()
		if end > total {
			end = total
		}
		return matched[start:end], total, nil
	}

	if pg == nil {
		cur, err := s.entities().Find(ctx, filter)
		if err != nil {
			return nil, 0, err
		}
		defer cur.Close(ctx)

		var all []*Entity
		if err := cur.All(ctx, &all); err != nil {
			return nil, 0, err
		}
		return all, 0, nil
	}

	total, err := s.entities().CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	opts := options.Find().SetSkip(pg.Skip()).SetLimit(pg.Take())
	cur, err := s.entities().Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cur.Close(ctx)

	list := []*Entity{}
	if err := cur.All(ctx, &list); err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

// UpdateEntity applies a partial update to an entity.
func (s *Service) UpdateEntity(ctx context.Context, id string, req UpdateEntityRequest) (*Entity, error) {
	set := bson.M{}
	if req.Type != nil {
		set["type"] = *req.Type
	}
	if req.Classification != nil {
		set["classification"] = *req.Classification
	}
	if req.Properties != nil {
		props := req.Properties
		if req.Label != nil {
			props["label"] = *req.Label
		}
		set["properties"] = props
	} else if req.Label != nil {
		set["properties.label"] = *req.Label
	}
	if len(set) == 0 {
		return s.GetEntity(ctx, id)
	}
	set["updated_at"] = time.Now()

	res, err := s.entities().UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": set})
	if err != nil {
		return nil, err
	}
	if res.MatchedCount == 0 {
		return nil, mongo.ErrNoDocuments
	}
	return s.GetEntity(ctx, id)
}

// DeleteEntity removes an entity along with every relationship it
// participates in (as either endpoint) and every case_items row referencing
// it, so no dangling references survive the delete.
func (s *Service) DeleteEntity(ctx context.Context, id string) error {
	res, err := s.entities().DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return mongo.ErrNoDocuments
	}

	if _, err := s.relationships().DeleteMany(ctx, bson.M{
		"$or": bson.A{
			bson.M{"entity_id_from": id},
			bson.M{"entity_id_to": id},
		},
	}); err != nil {
		return err
	}

	if _, err := s.caseEntities().DeleteMany(ctx, bson.M{"entity_id": id}); err != nil {
		return err
	}

	return nil
}

// DeleteRelationship removes a single relationship by ID.
func (s *Service) DeleteRelationship(ctx context.Context, id string) error {
	res, err := s.relationships().DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return mongo.ErrNoDocuments
	}
	return nil
}

func entityMatches(e *Entity, needle string) bool {
	if strings.Contains(strings.ToLower(e.Type), needle) {
		return true
	}
	for _, v := range e.Properties {
		if strings.Contains(strings.ToLower(valueToString(v)), needle) {
			return true
		}
	}
	return false
}

func valueToString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func (s *Service) CreateRelationship(ctx context.Context, req CreateRelationshipRequest) (*Relationship, error) {
	r := &Relationship{
		ID:           uuid.New().String(),
		EntityIDFrom: req.EntityIDFrom,
		EntityIDTo:   req.EntityIDTo,
		Type:         req.Type,
		Properties:   req.Properties,
		CreatedAt:    time.Now(),
	}
	if r.Properties == nil {
		r.Properties = map[string]interface{}{}
	}
	if _, err := s.relationships().InsertOne(ctx, r); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Service) Expand(ctx context.Context, nodeID string) ([]*Entity, []*Relationship, error) {
	cur, err := s.relationships().Find(ctx, bson.M{
		"$or": bson.A{
			bson.M{"entity_id_from": nodeID},
			bson.M{"entity_id_to": nodeID},
		},
	})
	if err != nil {
		return nil, nil, err
	}
	defer cur.Close(ctx)

	var rels []*Relationship
	if err := cur.All(ctx, &rels); err != nil {
		return nil, nil, err
	}

	nodeIDs := map[string]bool{nodeID: true}
	for _, r := range rels {
		nodeIDs[r.EntityIDFrom] = true
		nodeIDs[r.EntityIDTo] = true
	}

	entities, err := s.entitiesByIDs(ctx, keys(nodeIDs))
	if err != nil {
		return nil, nil, err
	}
	return entities, rels, nil
}

func (s *Service) FindPath(ctx context.Context, startID, endID string) ([]*Entity, []*Relationship, error) {
	// Load the full relationship set and BFS over an undirected graph.
	cur, err := s.relationships().Find(ctx, bson.M{})
	if err != nil {
		return nil, nil, err
	}
	defer cur.Close(ctx)

	var allRels []*Relationship
	if err := cur.All(ctx, &allRels); err != nil {
		return nil, nil, err
	}

	adj := map[string][]string{}
	for _, r := range allRels {
		adj[r.EntityIDFrom] = append(adj[r.EntityIDFrom], r.EntityIDTo)
		adj[r.EntityIDTo] = append(adj[r.EntityIDTo], r.EntityIDFrom)
	}

	// BFS with predecessor tracking (depth cap of 5 mirrors the old CTE).
	prev := map[string]string{startID: ""}
	depth := map[string]int{startID: 0}
	queue := []string{startID}
	found := startID == endID
	for len(queue) > 0 && !found {
		cur := queue[0]
		queue = queue[1:]
		if depth[cur] >= 5 {
			continue
		}
		for _, nb := range adj[cur] {
			if _, seen := prev[nb]; seen {
				continue
			}
			prev[nb] = cur
			depth[nb] = depth[cur] + 1
			if nb == endID {
				found = true
				break
			}
			queue = append(queue, nb)
		}
	}

	if _, ok := prev[endID]; !ok {
		return []*Entity{}, []*Relationship{}, nil
	}

	// Reconstruct the path start -> end.
	var path []string
	for at := endID; at != ""; at = prev[at] {
		path = append([]string{at}, path...)
		if at == startID {
			break
		}
	}
	pathSet := map[string]bool{}
	for _, id := range path {
		pathSet[id] = true
	}

	entities, err := s.entitiesByIDs(ctx, path)
	if err != nil {
		return nil, nil, err
	}

	// Relationships whose endpoints are both on the path.
	var rels []*Relationship
	for _, r := range allRels {
		if pathSet[r.EntityIDFrom] && pathSet[r.EntityIDTo] {
			rels = append(rels, r)
		}
	}
	return entities, rels, nil
}

func (s *Service) entitiesByIDs(ctx context.Context, ids []string) ([]*Entity, error) {
	if len(ids) == 0 {
		return []*Entity{}, nil
	}
	cur, err := s.entities().Find(ctx, bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var list []*Entity
	if err := cur.All(ctx, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
