package entities

import (
	"context"
	"sort"

	"go.mongodb.org/mongo-driver/bson"
)

// This file extends the graph capabilities already in service.go (Expand,
// FindPath/BFS) with shortest-path-as-canonical-route, common-neighbors, and
// aggregate graph stats — the analytics wave's graph endpoints.

/* ------------------------------ pure logic --------------------------------
   CommonNeighborIDs and DegreeCounts operate purely on an already-fetched
   []*Relationship, so they're unit-testable without a database (graph_test.go). */

// CommonNeighborIDs returns the (sorted, deduped) entity IDs directly
// connected — in either direction — to BOTH a and b, excluding a and b
// themselves.
func CommonNeighborIDs(rels []*Relationship, a, b string) []string {
	neighborsOf := func(id string) map[string]bool {
		out := map[string]bool{}
		for _, r := range rels {
			if r.EntityIDFrom == id {
				out[r.EntityIDTo] = true
			}
			if r.EntityIDTo == id {
				out[r.EntityIDFrom] = true
			}
		}
		return out
	}

	na := neighborsOf(a)
	nb := neighborsOf(b)

	var out []string
	for id := range na {
		if id == a || id == b {
			continue
		}
		if nb[id] {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// DegreeCounts returns, for every entity ID that appears in rels, the number
// of relationships it participates in (as either endpoint).
func DegreeCounts(rels []*Relationship) map[string]int {
	out := map[string]int{}
	for _, r := range rels {
		out[r.EntityIDFrom]++
		out[r.EntityIDTo]++
	}
	return out
}

// DegreeInfo is one row of the graph/stats "top connected" ranking.
type DegreeInfo struct {
	EntityID string `json:"entity_id"`
	Label    string `json:"label"`
	Type     string `json:"type"`
	Degree   int    `json:"degree"`
}

// topDegrees ranks a degree map descending by count and returns the top n
// (entity_id, degree) pairs, ties broken by entity_id for deterministic
// output.
func topDegrees(degrees map[string]int, n int) []struct {
	ID     string
	Degree int
} {
	rows := make([]struct {
		ID     string
		Degree int
	}, 0, len(degrees))
	for id, d := range degrees {
		rows = append(rows, struct {
			ID     string
			Degree int
		}{id, d})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Degree != rows[j].Degree {
			return rows[i].Degree > rows[j].Degree
		}
		return rows[i].ID < rows[j].ID
	})
	if len(rows) > n {
		rows = rows[:n]
	}
	return rows
}

/* --------------------------------- DB layer -------------------------------- */

// CommonNeighbors returns the entities directly connected to both a and b.
func (s *Service) CommonNeighbors(ctx context.Context, a, b string) ([]*Entity, error) {
	cur, err := s.relationships().Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var rels []*Relationship
	if err := cur.All(ctx, &rels); err != nil {
		return nil, err
	}

	ids := CommonNeighborIDs(rels, a, b)
	return s.entitiesByIDs(ctx, ids)
}

// GraphStats returns the top-10 most connected entities plus overall node/edge
// counts, for the analytics graph overview.
func (s *Service) GraphStats(ctx context.Context) ([]DegreeInfo, int64, int64, error) {
	totalNodes, err := s.entities().CountDocuments(ctx, bson.M{})
	if err != nil {
		return nil, 0, 0, err
	}
	totalEdges, err := s.relationships().CountDocuments(ctx, bson.M{})
	if err != nil {
		return nil, 0, 0, err
	}

	cur, err := s.relationships().Find(ctx, bson.M{})
	if err != nil {
		return nil, 0, 0, err
	}
	defer cur.Close(ctx)

	var rels []*Relationship
	if err := cur.All(ctx, &rels); err != nil {
		return nil, 0, 0, err
	}

	degrees := DegreeCounts(rels)
	top := topDegrees(degrees, 10)

	ids := make([]string, 0, len(top))
	for _, row := range top {
		ids = append(ids, row.ID)
	}
	ents, err := s.entitiesByIDs(ctx, ids)
	if err != nil {
		return nil, 0, 0, err
	}
	byID := make(map[string]*Entity, len(ents))
	for _, e := range ents {
		byID[e.ID] = e
	}

	out := make([]DegreeInfo, 0, len(top))
	for _, row := range top {
		info := DegreeInfo{EntityID: row.ID, Degree: row.Degree}
		if e, ok := byID[row.ID]; ok {
			info.Type = e.Type
			info.Label = labelOf(e)
		}
		out = append(out, info)
	}
	return out, totalNodes, totalEdges, nil
}

// labelOf picks a human-readable label from an entity's free-form
// properties: "label" wins, then "name", then falls back to the entity ID.
func labelOf(e *Entity) string {
	if e == nil {
		return ""
	}
	if v, ok := e.Properties["label"].(string); ok && v != "" {
		return v
	}
	if v, ok := e.Properties["name"].(string); ok && v != "" {
		return v
	}
	return e.ID
}
