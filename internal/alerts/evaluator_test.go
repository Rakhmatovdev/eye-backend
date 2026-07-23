package alerts

import "testing"

func TestEvaluateWatchlistDetection(t *testing.T) {
	watchlist := map[string]bool{"ent-009": true}
	dets := []DetectionInput{
		{ID: "det-1", EntityID: "ent-009", EntityName: "Timur Umarov"},
		{ID: "det-2", EntityID: "ent-001", EntityName: "Alisher Karimov"}, // not watchlisted
		{ID: "det-3", EntityID: "", EntityName: "Unattributed track"},    // no entity at all
	}

	got := EvaluateWatchlistDetection(dets, watchlist)
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate, got %d: %+v", len(got), got)
	}
	if got[0].DetectionID != "det-1" || got[0].EntityID != "ent-009" {
		t.Fatalf("unexpected candidate: %+v", got[0])
	}
	if got[0].Title == "" || got[0].Message == "" {
		t.Fatal("expected non-empty title/message")
	}
}

func TestEvaluateThreatClass(t *testing.T) {
	threats := []ThreatInput{
		{ID: "t-001", Designation: "HOSTILE-01", Classification: "hostile", EntityID: "ent-009"},
		{ID: "t-002", Designation: "SUSPECT-04", Classification: "suspect", EntityID: ""},
		{ID: "t-003", Designation: "HOSTILE-03", Classification: "Hostile", EntityID: ""}, // case-insensitive match
	}

	got := EvaluateThreatClass(threats, []string{"hostile"})
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates, got %d: %+v", len(got), got)
	}
	ids := map[string]bool{}
	for _, c := range got {
		ids[c.ThreatID] = true
	}
	if !ids["t-001"] || !ids["t-003"] {
		t.Fatalf("expected t-001 and t-003 to match, got %+v", got)
	}
}

func TestEvaluateThreatClass_NoClasses(t *testing.T) {
	threats := []ThreatInput{{ID: "t-001", Classification: "hostile"}}
	if got := EvaluateThreatClass(threats, nil); len(got) != 0 {
		t.Fatalf("expected no candidates with empty class filter, got %+v", got)
	}
}

func TestEvaluateRiskThreshold(t *testing.T) {
	ents := []EntityInput{
		{ID: "ent-009", Label: "Timur Umarov", RiskScore: 93, HasScore: true},
		{ID: "ent-003", Label: "Rustam Nazarov", RiskScore: 62, HasScore: true},
		{ID: "ent-099", Label: "No Score", HasScore: false},
	}

	got := EvaluateRiskThreshold(ents, 80)
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate, got %d: %+v", len(got), got)
	}
	if got[0].EntityID != "ent-009" {
		t.Fatalf("expected ent-009, got %+v", got[0])
	}
}

func TestEvaluateRiskThreshold_BoundaryIsInclusive(t *testing.T) {
	ents := []EntityInput{{ID: "ent-050", RiskScore: 80, HasScore: true}}
	got := EvaluateRiskThreshold(ents, 80)
	if len(got) != 1 {
		t.Fatalf("expected score == threshold to match (>=), got %+v", got)
	}
}

func TestDedupeKey(t *testing.T) {
	cases := []struct {
		name string
		cand Candidate
		want string
	}{
		{"detection wins", Candidate{DetectionID: "det-1", ThreatID: "t-1", EntityID: "ent-1"}, "rule-a|detection|det-1"},
		{"threat when no detection", Candidate{ThreatID: "t-1", EntityID: "ent-1"}, "rule-a|threat|t-1"},
		{"entity only", Candidate{EntityID: "ent-1"}, "rule-a|entity|ent-1"},
		{"nothing set", Candidate{}, "rule-a|unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DedupeKey("rule-a", tc.cand); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestDedupeKey_DifferentRulesDontCollide(t *testing.T) {
	c := Candidate{EntityID: "ent-1"}
	if DedupeKey("rule-a", c) == DedupeKey("rule-b", c) {
		t.Fatal("expected different rules to produce different dedupe keys for the same subject")
	}
}
