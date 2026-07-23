package entities

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// This file implements GET /entities/:id/report — a full analyst dossier
// assembled server-side as markdown (no PDF; the frontend renders/downloads
// the markdown directly). Sensor sightings and timeline events live in
// sibling packages' collections (detections, events); rather than importing
// internal/sensors / internal/events (and risking an import cycle down the
// line), this queries those collections directly by name — the same
// convention internal/ai's grounding queries already use.

// reportDetection/reportEvent/reportAlert mirror just the fields the report
// needs from the detections / events / alerts collections.
type reportDetection struct {
	ID         string    `bson:"_id"`
	SensorName string    `bson:"sensor_name"`
	Kind       string    `bson:"kind"`
	Confidence float64   `bson:"confidence"`
	Area       string    `bson:"area"`
	Timestamp  time.Time `bson:"timestamp"`
}

type reportEvent struct {
	ID          string    `bson:"_id"`
	Title       string    `bson:"title"`
	Description string    `bson:"description"`
	Type        string    `bson:"type"`
	Location    string    `bson:"location"`
	Timestamp   time.Time `bson:"timestamp"`
}

type reportAlert struct {
	ID           string    `bson:"_id"`
	RuleName     string    `bson:"rule_name"`
	Severity     string    `bson:"severity"`
	Title        string    `bson:"title"`
	Acknowledged bool      `bson:"acknowledged"`
	CreatedAt    time.Time `bson:"created_at"`
}

// GenerateReport assembles the full markdown dossier for a single entity:
// header/classification, attributes, 1-hop graph connections, sensor
// sightings, related timeline events, and related alerts.
func (s *Service) GenerateReport(ctx context.Context, id string) (string, error) {
	e, err := s.GetEntity(ctx, id)
	if err != nil {
		return "", err
	}

	neighbors, edges, err := s.Expand(ctx, id)
	if err != nil {
		return "", err
	}

	dets, err := s.reportDetections(ctx, id)
	if err != nil {
		return "", err
	}
	evs, err := s.reportEvents(ctx, id)
	if err != nil {
		return "", err
	}
	als, err := s.reportAlerts(ctx, id)
	if err != nil {
		return "", err
	}

	return BuildEntityReportMarkdown(e, neighbors, edges, dets, evs, als), nil
}

func (s *Service) reportDetections(ctx context.Context, entityID string) ([]reportDetection, error) {
	cur, err := s.db.Collection("detections").Find(ctx, bson.M{"entity_id": entityID})
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	defer cur.Close(ctx)
	var out []reportDetection
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) reportEvents(ctx context.Context, entityID string) ([]reportEvent, error) {
	cur, err := s.db.Collection("events").Find(ctx, bson.M{"entity_id": entityID})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var out []reportEvent
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) reportAlerts(ctx context.Context, entityID string) ([]reportAlert, error) {
	cur, err := s.db.Collection("alerts").Find(ctx, bson.M{"entity_id": entityID})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var out []reportAlert
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

/* ------------------------------ pure logic --------------------------------
   BuildEntityReportMarkdown takes only already-fetched Go values, so it's
   unit-testable with fake data (report_test.go), matching the DB-free test
   style used elsewhere in this codebase. */

// BuildEntityReportMarkdown assembles the full analyst dossier markdown.
func BuildEntityReportMarkdown(e *Entity, neighbors []*Entity, edges []*Relationship, dets []reportDetection, evs []reportEvent, als []reportAlert) string {
	var b strings.Builder
	label := labelOf(e)

	fmt.Fprintf(&b, "# Entity Dossier: %s\n\n", label)
	fmt.Fprintf(&b, "**Entity ID:** `%s`  \n", e.ID)
	fmt.Fprintf(&b, "**Type:** %s  \n", e.Type)
	fmt.Fprintf(&b, "**Classification:** %s  \n", strings.ToUpper(e.Classification))
	fmt.Fprintf(&b, "**Generated:** %s\n\n", time.Now().Format(time.RFC3339))

	b.WriteString("## Attributes\n\n")
	if len(e.Properties) == 0 {
		b.WriteString("_No properties recorded._\n\n")
	} else {
		for _, k := range sortedKeys(e.Properties) {
			fmt.Fprintf(&b, "- **%s:** %v\n", k, e.Properties[k])
		}
		b.WriteString("\n")
	}

	b.WriteString("## Graph Connections (1-hop)\n\n")
	if len(edges) == 0 {
		b.WriteString("_No known relationships._\n\n")
	} else {
		byID := map[string]*Entity{}
		for _, n := range neighbors {
			byID[n.ID] = n
		}
		for _, r := range edges {
			other := r.EntityIDTo
			if other == e.ID {
				other = r.EntityIDFrom
			}
			otherLabel := other
			if n, ok := byID[other]; ok {
				otherLabel = labelOf(n)
			}
			fmt.Fprintf(&b, "- **%s** → %s (`%s`)\n", r.Type, otherLabel, other)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Sensor Sightings\n\n")
	if len(dets) == 0 {
		b.WriteString("_No sensor sightings recorded._\n\n")
	} else {
		b.WriteString("| Time | Sensor | Kind | Confidence | Area |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, d := range dets {
			fmt.Fprintf(&b, "| %s | %s | %s | %.0f%% | %s |\n",
				d.Timestamp.Format(time.RFC3339), d.SensorName, d.Kind, d.Confidence*100, d.Area)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Related Timeline Events\n\n")
	if len(evs) == 0 {
		b.WriteString("_No timeline events recorded._\n\n")
	} else {
		for _, ev := range evs {
			fmt.Fprintf(&b, "- **%s** [%s] %s — %s\n", ev.Timestamp.Format("2006-01-02"), ev.Type, ev.Title, ev.Description)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Related Alerts\n\n")
	if len(als) == 0 {
		b.WriteString("_No related alerts._\n\n")
	} else {
		for _, a := range als {
			status := "open"
			if a.Acknowledged {
				status = "acknowledged"
			}
			fmt.Fprintf(&b, "- **[%s]** %s (rule: %s, %s) — %s\n",
				strings.ToUpper(a.Severity), a.Title, a.RuleName, status, a.CreatedAt.Format(time.RFC3339))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
