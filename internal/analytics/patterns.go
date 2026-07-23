package analytics

import (
	"fmt"
	"sort"
	"time"
)

// Every Detect* function in this file is pure — it operates only on
// already-fetched Go values, no I/O — so patterns_test.go can exercise them
// directly with fake data, matching the DB-free unit test style used
// elsewhere in this codebase. service.go wires these to live Mongo data.

func clampScore(s int) int {
	if s < 0 {
		return 0
	}
	if s > 100 {
		return 100
	}
	return s
}

/* ------------------------------- co_location ------------------------------- */

// DetectionRow is the subset of a sensors.Detection the co_location detector
// needs.
type DetectionRow struct {
	ID         string
	SensorID   string
	EntityID   string
	EntityName string
	Timestamp  time.Time
}

// DetectCoLocation flags pairs of distinct, identified entities detected by
// the SAME sensor within `window` of each other — a proxy for "these two
// people were physically near each other around the same time".
func DetectCoLocation(dets []DetectionRow, window time.Duration) []Pattern {
	bySensor := map[string][]DetectionRow{}
	for _, d := range dets {
		if d.EntityID == "" {
			continue
		}
		bySensor[d.SensorID] = append(bySensor[d.SensorID], d)
	}

	var out []Pattern
	seenPairs := map[string]bool{}
	for sensorID, rows := range bySensor {
		sort.Slice(rows, func(i, j int) bool { return rows[i].Timestamp.Before(rows[j].Timestamp) })
		for i := 0; i < len(rows); i++ {
			for j := i + 1; j < len(rows); j++ {
				gap := rows[j].Timestamp.Sub(rows[i].Timestamp)
				if gap > window {
					break // rows sorted by time — nothing further in range
				}
				if rows[i].EntityID == rows[j].EntityID {
					continue
				}
				a, b := rows[i].EntityID, rows[j].EntityID
				pairKey := sensorID + "|" + minMax(a, b)
				if seenPairs[pairKey] {
					continue
				}
				seenPairs[pairKey] = true

				out = append(out, Pattern{
					Type:  "co_location",
					Score: clampScore(60 + int(window.Minutes()-gap.Minutes())),
					Title: fmt.Sprintf("Co-location: %s & %s", nameOrID(rows[i].EntityName, a), nameOrID(rows[j].EntityName, b)),
					Description: fmt.Sprintf("%s and %s were both detected by sensor %s within %s of each other.",
						nameOrID(rows[i].EntityName, a), nameOrID(rows[j].EntityName, b), sensorID, gap.Round(time.Minute)),
					EntityIDs: []string{a, b},
					Evidence: []string{
						fmt.Sprintf("detection %s at %s (sensor %s)", rows[i].ID, rows[i].Timestamp.Format(time.RFC3339), sensorID),
						fmt.Sprintf("detection %s at %s (sensor %s)", rows[j].ID, rows[j].Timestamp.Format(time.RFC3339), sensorID),
					},
				})
			}
		}
	}
	return out
}

func minMax(a, b string) string {
	if a < b {
		return a + "," + b
	}
	return b + "," + a
}

func nameOrID(name, id string) string {
	if name != "" {
		return name
	}
	return id
}

/* -------------------------------- hub_entity -------------------------------- */

// DetectHubEntities flags entities whose relationship degree is at least 2x
// the mean degree across the graph.
func DetectHubEntities(degrees map[string]int, labels map[string]string) []Pattern {
	if len(degrees) == 0 {
		return nil
	}
	total := 0
	for _, d := range degrees {
		total += d
	}
	mean := float64(total) / float64(len(degrees))
	if mean <= 0 {
		return nil
	}

	var out []Pattern
	for id, d := range degrees {
		if float64(d) < 2*mean {
			continue
		}
		label := labels[id]
		out = append(out, Pattern{
			Type:        "hub_entity",
			Score:       clampScore(40 + d*8),
			Title:       fmt.Sprintf("Hub entity: %s", nameOrID(label, id)),
			Description: fmt.Sprintf("%s has %d relationships, at least 2x the graph's mean degree of %.1f.", nameOrID(label, id), d, mean),
			EntityIDs:   []string{id},
			Evidence:    []string{fmt.Sprintf("degree=%d mean_degree=%.2f", d, mean)},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

/* --------------------------- threat_correlation ---------------------------- */

// ThreatRow is the subset of a military.Threat the threat_correlation
// detector needs.
type ThreatRow struct {
	ID             string
	Designation    string
	Classification string
	EntityID       string
}

// DetectThreatCorrelation flags a military threat track that is linked
// (via entity_id) to an entity that is either watchlisted or high-risk.
func DetectThreatCorrelation(threats []ThreatRow, watchlist map[string]bool, highRisk map[string]bool, labels map[string]string) []Pattern {
	var out []Pattern
	for _, t := range threats {
		if t.EntityID == "" {
			continue
		}
		onWatch := watchlist[t.EntityID]
		hi := highRisk[t.EntityID]
		if !onWatch && !hi {
			continue
		}
		reason := "high-risk"
		if onWatch {
			reason = "watchlisted"
		}
		label := nameOrID(labels[t.EntityID], t.EntityID)
		out = append(out, Pattern{
			Type:        "threat_correlation",
			Score:       85,
			Title:       fmt.Sprintf("Threat linked to %s entity", reason),
			Description: fmt.Sprintf("Track %s (classification: %s) is linked to entity %s, which is %s.", t.Designation, t.Classification, label, reason),
			EntityIDs:   []string{t.EntityID},
			Evidence:    []string{fmt.Sprintf("threat_id=%s classification=%s entity_id=%s", t.ID, t.Classification, t.EntityID)},
		})
	}
	return out
}

/* ---------------------------- burst_activity -------------------------------- */

// ActivityRow is one timestamped occurrence tied to an entity — a sensor
// detection or a timeline event, whichever the caller is measuring "activity
// volume" from.
type ActivityRow struct {
	EntityID  string
	Timestamp time.Time
}

// DetectBurstActivity flags entities with unusually high activity (detections
// + timeline events) in the last 24h versus their prior-24h baseline: at
// least minCount occurrences in the last 24h, AND either no prior baseline
// (a first-time burst) or at least `multiplier`x the baseline.
func DetectBurstActivity(rows []ActivityRow, now time.Time, minCount int, multiplier float64, labels map[string]string) []Pattern {
	last24 := map[string]int{}
	prev24 := map[string]int{}
	for _, r := range rows {
		if r.EntityID == "" {
			continue
		}
		age := now.Sub(r.Timestamp)
		if age < 0 {
			continue
		}
		switch {
		case age <= 24*time.Hour:
			last24[r.EntityID]++
		case age <= 48*time.Hour:
			prev24[r.EntityID]++
		}
	}

	var out []Pattern
	for id, count := range last24 {
		if count < minCount {
			continue
		}
		baseline := prev24[id]
		if baseline > 0 && float64(count) < float64(baseline)*multiplier {
			continue
		}
		label := nameOrID(labels[id], id)
		out = append(out, Pattern{
			Type:        "burst_activity",
			Score:       clampScore(30 + count*6),
			Title:       fmt.Sprintf("Activity burst: %s", label),
			Description: fmt.Sprintf("%s had %d detections/events in the last 24h vs a baseline of %d in the prior 24h.", label, count, baseline),
			EntityIDs:   []string{id},
			Evidence:    []string{fmt.Sprintf("count_24h=%d baseline_24h=%d", count, baseline)},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}
