package entities

import (
	"strings"
	"testing"
	"time"
)

func TestBuildEntityReportMarkdown_IncludesAllSections(t *testing.T) {
	e := &Entity{
		ID:             "ent-009",
		Type:           "person",
		Classification: "secret",
		Properties:     map[string]interface{}{"name": "Timur Umarov", "risk_score": 93},
	}
	neighbors := []*Entity{
		{ID: "ent-019", Type: "organization", Properties: map[string]interface{}{"name": "CryptoAsia Exchange"}},
	}
	edges := []*Relationship{
		{EntityIDFrom: "ent-009", EntityIDTo: "ent-019", Type: "uses"},
	}
	dets := []reportDetection{
		{ID: "det-016", SensorName: "UAV Shadow-3 (loiter)", Kind: "thermal", Confidence: 0.74, Area: "Dushanbe approach", Timestamp: time.Now()},
	}
	evs := []reportEvent{
		{ID: "ev-006", Title: "Hawala Transfer Flagged", Description: "informal value transfer", Type: "financial", Timestamp: time.Now()},
	}
	als := []reportAlert{
		{ID: "al-1", RuleName: "Watchlist detection", Severity: "high", Title: "Watchlisted entity detected", Acknowledged: false, CreatedAt: time.Now()},
	}

	md := BuildEntityReportMarkdown(e, neighbors, edges, dets, evs, als)

	for _, want := range []string{
		"# Entity Dossier: Timur Umarov",
		"ent-009",
		"SECRET",
		"risk_score",
		"CryptoAsia Exchange",
		"UAV Shadow-3 (loiter)",
		"Hawala Transfer Flagged",
		"Watchlisted entity detected",
		"## Attributes",
		"## Graph Connections (1-hop)",
		"## Sensor Sightings",
		"## Related Timeline Events",
		"## Related Alerts",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("expected markdown to contain %q, got:\n%s", want, md)
		}
	}
}

func TestBuildEntityReportMarkdown_EmptySectionsDontPanic(t *testing.T) {
	e := &Entity{ID: "ent-x", Type: "person", Classification: "public", Properties: map[string]interface{}{}}

	md := BuildEntityReportMarkdown(e, nil, nil, nil, nil, nil)

	for _, want := range []string{
		"No properties recorded",
		"No known relationships",
		"No sensor sightings recorded",
		"No timeline events recorded",
		"No related alerts",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("expected empty-state markdown to contain %q, got:\n%s", want, md)
		}
	}
}
