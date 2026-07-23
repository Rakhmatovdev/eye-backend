package analytics

import (
	"testing"
	"time"
)

func TestDetectCoLocation_FlagsPairWithinWindow(t *testing.T) {
	base := time.Now()
	dets := []DetectionRow{
		{ID: "det-1", SensorID: "cam-001", EntityID: "ent-001", EntityName: "Alisher Karimov", Timestamp: base},
		{ID: "det-2", SensorID: "cam-001", EntityID: "ent-002", EntityName: "Zhang Wei", Timestamp: base.Add(5 * time.Minute)},
		// same entity twice — must not pair with itself
		{ID: "det-3", SensorID: "cam-001", EntityID: "ent-001", EntityName: "Alisher Karimov", Timestamp: base.Add(6 * time.Minute)},
		// different sensor, out of window — must not match
		{ID: "det-4", SensorID: "cam-002", EntityID: "ent-003", EntityName: "Rustam Nazarov", Timestamp: base.Add(2 * time.Hour)},
	}

	got := DetectCoLocation(dets, 30*time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected 1 co-location pattern, got %d: %+v", len(got), got)
	}
	p := got[0]
	if p.Type != "co_location" {
		t.Fatalf("expected type co_location, got %s", p.Type)
	}
	if len(p.EntityIDs) != 2 {
		t.Fatalf("expected 2 entity ids, got %+v", p.EntityIDs)
	}
	if len(p.Evidence) != 2 {
		t.Fatalf("expected 2 evidence items, got %+v", p.Evidence)
	}
}

func TestDetectCoLocation_OutsideWindowNoMatch(t *testing.T) {
	base := time.Now()
	dets := []DetectionRow{
		{ID: "det-1", SensorID: "cam-001", EntityID: "ent-001", Timestamp: base},
		{ID: "det-2", SensorID: "cam-001", EntityID: "ent-002", Timestamp: base.Add(45 * time.Minute)},
	}
	got := DetectCoLocation(dets, 30*time.Minute)
	if len(got) != 0 {
		t.Fatalf("expected no pattern outside the window, got %+v", got)
	}
}

func TestDetectHubEntities(t *testing.T) {
	// mean degree = (10+1+1+1+1)/5 = 2.8; only "hub" (10) clears 2x mean.
	degrees := map[string]int{"hub": 10, "a": 1, "b": 1, "c": 1, "d": 1}
	labels := map[string]string{"hub": "Dragon Capital Investment"}

	got := DetectHubEntities(degrees, labels)
	if len(got) != 1 {
		t.Fatalf("expected 1 hub pattern, got %d: %+v", len(got), got)
	}
	if got[0].EntityIDs[0] != "hub" {
		t.Fatalf("expected hub entity flagged, got %+v", got[0])
	}
	if got[0].Type != "hub_entity" {
		t.Fatalf("expected type hub_entity, got %s", got[0].Type)
	}
}

func TestDetectHubEntities_NoHubWhenEvenlyDistributed(t *testing.T) {
	degrees := map[string]int{"a": 2, "b": 2, "c": 2}
	got := DetectHubEntities(degrees, nil)
	if len(got) != 0 {
		t.Fatalf("expected no hub entities when degree is uniform, got %+v", got)
	}
}

func TestDetectThreatCorrelation(t *testing.T) {
	threats := []ThreatRow{
		{ID: "t-001", Designation: "HOSTILE-01", Classification: "hostile", EntityID: "ent-009"}, // watchlisted
		{ID: "t-002", Designation: "SUSPECT-04", Classification: "suspect", EntityID: "ent-020"},  // high-risk only
		{ID: "t-003", Designation: "UNKNOWN-07", Classification: "unknown", EntityID: "ent-030"},  // neither
		{ID: "t-004", Designation: "SUSPECT-09", Classification: "suspect", EntityID: ""},          // no entity link
	}
	watchlist := map[string]bool{"ent-009": true}
	highRisk := map[string]bool{"ent-020": true}
	labels := map[string]string{"ent-009": "Timur Umarov", "ent-020": "Someone Else"}

	got := DetectThreatCorrelation(threats, watchlist, highRisk, labels)
	if len(got) != 2 {
		t.Fatalf("expected 2 correlated threats, got %d: %+v", len(got), got)
	}
	ids := map[string]bool{}
	for _, p := range got {
		ids[p.EntityIDs[0]] = true
	}
	if !ids["ent-009"] || !ids["ent-020"] {
		t.Fatalf("expected ent-009 and ent-020 to be flagged, got %+v", got)
	}
}

func TestDetectBurstActivity(t *testing.T) {
	now := time.Now()
	rows := []ActivityRow{
		// ent-burst: 4 events in the last 24h, only 1 in the prior 24h — a burst.
		{EntityID: "ent-burst", Timestamp: now.Add(-1 * time.Hour)},
		{EntityID: "ent-burst", Timestamp: now.Add(-2 * time.Hour)},
		{EntityID: "ent-burst", Timestamp: now.Add(-3 * time.Hour)},
		{EntityID: "ent-burst", Timestamp: now.Add(-4 * time.Hour)},
		{EntityID: "ent-burst", Timestamp: now.Add(-30 * time.Hour)},
		// ent-steady: 2 in last 24h, 2 in prior 24h — not a burst (below minCount and not above multiplier).
		{EntityID: "ent-steady", Timestamp: now.Add(-1 * time.Hour)},
		{EntityID: "ent-steady", Timestamp: now.Add(-2 * time.Hour)},
		{EntityID: "ent-steady", Timestamp: now.Add(-25 * time.Hour)},
		{EntityID: "ent-steady", Timestamp: now.Add(-26 * time.Hour)},
	}

	got := DetectBurstActivity(rows, now, 3, 1.5, map[string]string{"ent-burst": "Timur Umarov"})
	if len(got) != 1 {
		t.Fatalf("expected 1 burst pattern, got %d: %+v", len(got), got)
	}
	if got[0].EntityIDs[0] != "ent-burst" {
		t.Fatalf("expected ent-burst flagged, got %+v", got[0])
	}
}

func TestDetectBurstActivity_IgnoresFutureAndEmptyEntity(t *testing.T) {
	now := time.Now()
	rows := []ActivityRow{
		{EntityID: "", Timestamp: now}, // no entity — must be skipped
		{EntityID: "ent-x", Timestamp: now.Add(time.Hour)}, // future timestamp — skipped
	}
	got := DetectBurstActivity(rows, now, 1, 1.5, nil)
	if len(got) != 0 {
		t.Fatalf("expected no patterns, got %+v", got)
	}
}
