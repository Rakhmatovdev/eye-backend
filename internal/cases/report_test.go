package cases

import (
	"strings"
	"testing"
	"time"

	"intelligence-platform/internal/entities"
)

func TestLabelOf(t *testing.T) {
	e := &entities.Entity{ID: "ent-001", Properties: map[string]interface{}{"name": "Alisher Karimov"}}
	if got := labelOf(e); got != "Alisher Karimov" {
		t.Fatalf("expected name to win, got %q", got)
	}

	e2 := &entities.Entity{ID: "ent-002", Properties: map[string]interface{}{}}
	if got := labelOf(e2); got != "ent-002" {
		t.Fatalf("expected fallback to ID, got %q", got)
	}
}

func TestMiniSummaryOf(t *testing.T) {
	e := &entities.Entity{
		Type:           "person",
		Classification: "confidential",
		Properties:     map[string]interface{}{"risk_score": 78, "nationality": "Uzbekistani"},
	}
	got := miniSummaryOf(e)
	if !strings.Contains(got, "risk score 78") || !strings.Contains(got, "Uzbekistani") {
		t.Fatalf("expected summary to mention risk score and nationality, got %q", got)
	}
}

func TestMiniSummaryOf_FallsBackWhenNoProperties(t *testing.T) {
	e := &entities.Entity{Type: "location", Classification: "public", Properties: map[string]interface{}{}}
	got := miniSummaryOf(e)
	if !strings.Contains(got, "location entity") || !strings.Contains(got, "public") {
		t.Fatalf("expected generic fallback summary, got %q", got)
	}
}

func TestBuildCaseReportMarkdown_IncludesAllSections(t *testing.T) {
	c := &Case{
		ID: "case-1", Title: "Silk Road Investigation", Status: "open", Priority: "high",
		Classification: "confidential", OwnerID: "analyst-1", Description: "Tracking shell company activity.",
		CreatedAt: time.Now(),
	}
	ents := []reportEntitySummary{
		{ID: "ent-001", Label: "Alisher Karimov", Type: "person", Classification: "confidential", Summary: "risk score 78"},
	}
	now := time.Now()
	timeline := []reportTimelineItem{
		{EntityID: "ent-001", EntityLabel: "Alisher Karimov", Timestamp: now.Add(-time.Hour), Title: "Border Crossing", Description: "Crossed at Dostuk", Type: "border"},
		{EntityID: "ent-001", EntityLabel: "Alisher Karimov", Timestamp: now.Add(-2 * time.Hour), Title: "Departed Tashkent", Description: "Flight UZ-204", Type: "travel"},
	}
	alerts := []reportCaseAlert{
		{EntityLabel: "Alisher Karimov", RuleName: "High risk entity", Severity: "high", Title: "High risk entity", Acknowledged: true, CreatedAt: now},
	}

	md := BuildCaseReportMarkdown(c, ents, timeline, alerts)

	for _, want := range []string{
		"# Case Dossier: Silk Road Investigation",
		"case-1",
		"Tracking shell company activity.",
		"Alisher Karimov",
		"risk score 78",
		"Border Crossing",
		"Departed Tashkent",
		"High risk entity",
		"## Linked Entities",
		"## Timeline",
		"## Related Alerts",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("expected markdown to contain %q, got:\n%s", want, md)
		}
	}
}

func TestSortedTimeline_OrdersOldestFirst(t *testing.T) {
	now := time.Now()
	items := []reportTimelineItem{
		{Title: "later", Timestamp: now},
		{Title: "earliest", Timestamp: now.Add(-2 * time.Hour)},
		{Title: "middle", Timestamp: now.Add(-time.Hour)},
	}
	sorted := sortedTimeline(items)
	if sorted[0].Title != "earliest" || sorted[1].Title != "middle" || sorted[2].Title != "later" {
		t.Fatalf("expected chronological order, got %+v", sorted)
	}
	// original slice must be untouched
	if items[0].Title != "later" {
		t.Fatal("sortedTimeline must not mutate its input")
	}
}
