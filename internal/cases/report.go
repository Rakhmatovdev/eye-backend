package cases

import (
	"context"
	"fmt"
	"strings"
	"time"

	"intelligence-platform/internal/entities"

	"go.mongodb.org/mongo-driver/bson"
)

// This file implements GET /cases/:id/report — a full case dossier assembled
// server-side as markdown: case meta, linked entities each with a mini
// summary, and a merged timeline. Related alerts/events live in sibling
// packages' collections; this queries them directly by name (same convention
// internal/ai's grounding queries and internal/entities' report.go use)
// rather than importing those packages, to keep this self-contained.

// reportEntitySummary is a linked entity plus a one-line mini-summary.
type reportEntitySummary struct {
	ID             string
	Label          string
	Type           string
	Classification string
	Summary        string
}

// reportTimelineItem is one row of the merged case timeline.
type reportTimelineItem struct {
	EntityID    string
	EntityLabel string
	Timestamp   time.Time
	Title       string
	Description string
	Type        string
}

// reportCaseAlert is one alert related to any entity linked to the case.
type reportCaseAlert struct {
	EntityLabel  string
	RuleName     string
	Severity     string
	Title        string
	Acknowledged bool
	CreatedAt    time.Time
}

// GenerateReport assembles the full markdown dossier for a case: case meta,
// linked entities each with a mini-summary, and a merged timeline of events
// + related alerts across every linked entity.
func (s *Service) GenerateReport(ctx context.Context, id string) (string, error) {
	c, err := s.Get(ctx, id)
	if err != nil {
		return "", err
	}

	ents, err := s.GetEntities(ctx, id)
	if err != nil {
		return "", err
	}

	summaries := make([]reportEntitySummary, 0, len(ents))
	entityIDs := make([]string, 0, len(ents))
	labelByID := map[string]string{}
	for _, e := range ents {
		label := labelOf(e)
		labelByID[e.ID] = label
		entityIDs = append(entityIDs, e.ID)
		summaries = append(summaries, reportEntitySummary{
			ID:             e.ID,
			Label:          label,
			Type:           e.Type,
			Classification: e.Classification,
			Summary:        miniSummaryOf(e),
		})
	}

	timeline, err := s.reportTimeline(ctx, entityIDs, labelByID)
	if err != nil {
		return "", err
	}
	alerts, err := s.reportAlerts(ctx, entityIDs, labelByID)
	if err != nil {
		return "", err
	}

	return BuildCaseReportMarkdown(c, summaries, timeline, alerts), nil
}

func (s *Service) reportTimeline(ctx context.Context, entityIDs []string, labelByID map[string]string) ([]reportTimelineItem, error) {
	if len(entityIDs) == 0 {
		return nil, nil
	}
	cur, err := s.db.Collection("events").Find(ctx, bson.M{"entity_id": bson.M{"$in": entityIDs}})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var rows []struct {
		EntityID    string    `bson:"entity_id"`
		Title       string    `bson:"title"`
		Description string    `bson:"description"`
		Type        string    `bson:"type"`
		Timestamp   time.Time `bson:"timestamp"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}

	out := make([]reportTimelineItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, reportTimelineItem{
			EntityID:    r.EntityID,
			EntityLabel: labelByID[r.EntityID],
			Timestamp:   r.Timestamp,
			Title:       r.Title,
			Description: r.Description,
			Type:        r.Type,
		})
	}
	return out, nil
}

func (s *Service) reportAlerts(ctx context.Context, entityIDs []string, labelByID map[string]string) ([]reportCaseAlert, error) {
	if len(entityIDs) == 0 {
		return nil, nil
	}
	cur, err := s.db.Collection("alerts").Find(ctx, bson.M{"entity_id": bson.M{"$in": entityIDs}})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var rows []struct {
		EntityID     string    `bson:"entity_id"`
		RuleName     string    `bson:"rule_name"`
		Severity     string    `bson:"severity"`
		Title        string    `bson:"title"`
		Acknowledged bool      `bson:"acknowledged"`
		CreatedAt    time.Time `bson:"created_at"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}

	out := make([]reportCaseAlert, 0, len(rows))
	for _, r := range rows {
		out = append(out, reportCaseAlert{
			EntityLabel:  labelByID[r.EntityID],
			RuleName:     r.RuleName,
			Severity:     r.Severity,
			Title:        r.Title,
			Acknowledged: r.Acknowledged,
			CreatedAt:    r.CreatedAt,
		})
	}
	return out, nil
}

/* ------------------------------ pure logic --------------------------------
   BuildCaseReportMarkdown / labelOf / miniSummaryOf take only already-fetched
   Go values, so they're unit-testable with fake data (report_test.go). */

// BuildCaseReportMarkdown assembles the full case dossier markdown.
func BuildCaseReportMarkdown(c *Case, ents []reportEntitySummary, timeline []reportTimelineItem, alerts []reportCaseAlert) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Case Dossier: %s\n\n", c.Title)
	fmt.Fprintf(&b, "**Case ID:** `%s`  \n", c.ID)
	fmt.Fprintf(&b, "**Status:** %s  \n", c.Status)
	fmt.Fprintf(&b, "**Priority:** %s  \n", c.Priority)
	fmt.Fprintf(&b, "**Classification:** %s  \n", strings.ToUpper(c.Classification))
	fmt.Fprintf(&b, "**Owner:** %s  \n", c.OwnerID)
	fmt.Fprintf(&b, "**Opened:** %s  \n", c.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "**Generated:** %s\n\n", time.Now().Format(time.RFC3339))

	if c.Description != "" {
		fmt.Fprintf(&b, "## Summary\n\n%s\n\n", c.Description)
	}

	b.WriteString("## Linked Entities\n\n")
	if len(ents) == 0 {
		b.WriteString("_No entities linked to this case._\n\n")
	} else {
		for _, e := range ents {
			fmt.Fprintf(&b, "### %s (`%s`)\n\n", e.Label, e.ID)
			fmt.Fprintf(&b, "- **Type:** %s\n", e.Type)
			fmt.Fprintf(&b, "- **Classification:** %s\n", strings.ToUpper(e.Classification))
			fmt.Fprintf(&b, "- **Summary:** %s\n\n", e.Summary)
		}
	}

	b.WriteString("## Timeline\n\n")
	if len(timeline) == 0 {
		b.WriteString("_No timeline events recorded for linked entities._\n\n")
	} else {
		for _, ev := range sortedTimeline(timeline) {
			fmt.Fprintf(&b, "- **%s** [%s] %s (%s) — %s\n",
				ev.Timestamp.Format("2006-01-02"), ev.Type, ev.Title, ev.EntityLabel, ev.Description)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Related Alerts\n\n")
	if len(alerts) == 0 {
		b.WriteString("_No related alerts._\n\n")
	} else {
		for _, a := range alerts {
			status := "open"
			if a.Acknowledged {
				status = "acknowledged"
			}
			fmt.Fprintf(&b, "- **[%s]** %s (%s, rule: %s, %s) — %s\n",
				strings.ToUpper(a.Severity), a.Title, a.EntityLabel, a.RuleName, status, a.CreatedAt.Format(time.RFC3339))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func sortedTimeline(items []reportTimelineItem) []reportTimelineItem {
	out := make([]reportTimelineItem, len(items))
	copy(out, items)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Timestamp.After(out[j].Timestamp); j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// labelOf picks a human-readable label from an entity's free-form
// properties: "label" wins, then "name", then falls back to the entity ID.
// Mirrors internal/entities' own labelOf helper (kept local/unexported to
// avoid exporting an implementation detail across the package boundary).
func labelOf(e *entities.Entity) string {
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

// miniSummaryOf builds a one-line summary for a linked entity from its
// free-form properties (risk score, tags, nationality — whichever are
// present).
func miniSummaryOf(e *entities.Entity) string {
	var parts []string
	if v, ok := e.Properties["risk_score"]; ok {
		parts = append(parts, fmt.Sprintf("risk score %v", v))
	}
	if v, ok := e.Properties["nationality"].(string); ok && v != "" {
		parts = append(parts, v)
	}
	if v, ok := e.Properties["tags"].(string); ok && v != "" {
		parts = append(parts, "tags: "+v)
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%s entity, classification %s", e.Type, e.Classification)
	}
	return strings.Join(parts, "; ")
}
