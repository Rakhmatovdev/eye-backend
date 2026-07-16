package realtime

import (
	"math/rand"
	"strconv"
	"time"
)

// This file adds a second live-feed layer on top of the hub's existing
// cyber-threat (`type: "threat"`) simulation in hub.go. It rotates through a
// small set of templates lifted from the seed data (internal/seed/seed.go) —
// same entities, sensors, and hostile tracks the REST API already returns —
// so the demo feed reads as one coherent picture rather than random noise.
//
// `StartBroadcaster` is started once from cmd/api/main.go right after
// `go wsHub.Run()`. It only ever writes to the hub's exported Broadcast
// channel (via broadcastIfConnected), so it can't race with hub.Run's own
// goroutine.

// detectionTemplates mirror the sensors/detections seed rows: "which sensor
// saw whom, where". Consumed by the user panel's Surveillance detection feed.
var detectionTemplates = []map[string]interface{}{
	{"sensor_id": "cam-002", "sensor_name": "TAS Airport — Passport Control", "entity_id": "ent-001", "entity_name": "Alisher Karimov", "kind": "face_match", "confidence": 0.96, "lat": 41.2585, "lng": 69.2805, "area": "Tashkent Intl Airport"},
	{"sensor_id": "sig-001", "sensor_name": "SIGINT Collector Alpha", "entity_id": "ent-001", "entity_name": "Alisher Karimov", "kind": "signal", "confidence": 0.82, "lat": 41.2995, "lng": 69.2401, "area": "Tashkent metro"},
	{"sensor_id": "drn-002", "sensor_name": "UAV Shadow-3 (loiter)", "entity_id": "ent-009", "entity_name": "Timur Umarov", "kind": "thermal", "confidence": 0.71, "lat": 38.5598, "lng": 68.7739, "area": "Dushanbe approach"},
	{"sensor_id": "cam-005", "sensor_name": "Almaty BC — Dragon Capital Lobby", "entity_id": "ent-002", "entity_name": "Zhang Wei", "kind": "face_match", "confidence": 0.88, "lat": 43.2220, "lng": 76.8512, "area": "Almaty Business Center"},
	{"sensor_id": "cam-003", "sensor_name": "Dostuk Border — Lane 3 ANPR", "entity_id": "ent-005", "entity_name": "Bekzod Toshmatov", "kind": "plate_match", "confidence": 0.99, "lat": 40.7700, "lng": 69.2900, "area": "Dostuk Border Crossing"},
	{"sensor_id": "cam-006", "sensor_name": "Samarkand — Registon Sq.", "entity_id": "ent-003", "entity_name": "Rustam Nazarov", "kind": "face_match", "confidence": 0.85, "lat": 39.6542, "lng": 66.9597, "area": "Samarkand"},
	{"sensor_id": "rad-001", "sensor_name": "Border Radar North", "entity_id": "", "entity_name": "Unattributed track", "kind": "motion", "confidence": 0.60, "lat": 42.3417, "lng": 69.5901, "area": "Shymkent sector"},
	{"sensor_id": "drn-001", "sensor_name": "UAV Reaper-7 (patrol)", "entity_id": "ent-009", "entity_name": "Timur Umarov", "kind": "thermal", "confidence": 0.74, "lat": 40.7841, "lng": 72.3417, "area": "Fergana Valley"},
}

// incidentTemplates mirror the security incidents domain — SOC-style
// findings, some correlated to hostile threat tracks / watched entities.
var incidentTemplates = []map[string]interface{}{
	{"type": "intrusion", "severity": "critical", "title": "Perimeter track correlated with HOSTILE-01 convoy", "description": "Sensor fusion correlates SIGINT + radar returns for hostile convoy HOSTILE-01 approaching the Dushanbe–Termez corridor.", "source_ip": "10.44.2.18", "entity_id": "ent-009"},
	{"type": "unauthorized_access", "severity": "high", "title": "Anomalous dossier access — ent-001", "description": "User session flagged for repeated access to the Alisher Karimov dossier outside normal duty hours.", "source_ip": "172.16.5.91", "entity_id": "ent-001"},
	{"type": "exfiltration", "severity": "medium", "title": "Data export threshold exceeded", "description": "API key linked to CryptoAsia Exchange monitoring exceeded its data export volume threshold.", "source_ip": "203.0.113.44", "entity_id": "ent-019"},
	{"type": "sensor_tamper", "severity": "medium", "title": "Sensor heartbeat anomaly — cam-004", "description": "Yunusabad — Silk Road Office camera reporting a degraded signal; possible tamper or obstruction.", "source_ip": "10.0.14.4", "entity_id": ""},
	{"type": "signal_jamming", "severity": "high", "title": "Suspected signal jamming near Dushanbe approach", "description": "UAV Shadow-3 loiter track reports intermittent signal loss consistent with jamming near Timur Umarov's last known position.", "source_ip": "10.0.9.2", "entity_id": "ent-009"},
	{"type": "border_alert", "severity": "high", "title": "ANPR hit queued for manual review", "description": "Dostuk Border Lane 3 ANPR logged a plate match against a watchlisted vehicle associated with Bekzod Toshmatov.", "source_ip": "10.12.3.7", "entity_id": "ent-005"},
}

var broadcasterCounter int64

func nextID(prefix string) string {
	broadcasterCounter++
	return prefix + "-" + strconv.FormatInt(time.Now().Unix(), 36) + "-" + strconv.FormatInt(broadcasterCounter, 36)
}

// jitter nudges a float by up to +/-pct of its magnitude so repeated frames
// from the same template don't look robotic.
func jitter(v, pct float64) float64 {
	delta := v * pct * (rand.Float64()*2 - 1)
	return v + delta
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// StartBroadcaster runs the sensor-detection and security-incident live feed
// loops. It's a deliberately simple deterministic-ish simulation: rotate
// through a small template set, jitter numeric fields, stamp "now", push.
// Call once, in a goroutine, after wsHub.Run() has started.
func StartBroadcaster(h *Hub) {
	detTicker := time.NewTicker(3500 * time.Millisecond)
	incTicker := time.NewTicker(9 * time.Second)
	defer detTicker.Stop()
	defer incTicker.Stop()

	for {
		select {
		case <-detTicker.C:
			tpl := detectionTemplates[rand.Intn(len(detectionTemplates))]
			conf, _ := tpl["confidence"].(float64)
			lat, _ := tpl["lat"].(float64)
			lng, _ := tpl["lng"].(float64)
			msg := map[string]interface{}{
				"type": "detection",
				"data": map[string]interface{}{
					"id":          nextID("det"),
					"sensor_id":   tpl["sensor_id"],
					"sensor_name": tpl["sensor_name"],
					"entity_id":   tpl["entity_id"],
					"entity_name": tpl["entity_name"],
					"kind":        tpl["kind"],
					"confidence":  clamp01(jitter(conf, 0.03)),
					"lat":         jitter(lat, 0.002),
					"lng":         jitter(lng, 0.002),
					"area":        tpl["area"],
					"timestamp":   time.Now().Format(time.RFC3339),
				},
			}
			h.broadcastIfConnected(msg)

		case <-incTicker.C:
			tpl := incidentTemplates[rand.Intn(len(incidentTemplates))]
			msg := map[string]interface{}{
				"type": "incident",
				"data": map[string]interface{}{
					"id":          nextID("inc"),
					"type":        tpl["type"],
					"severity":    tpl["severity"],
					"title":       tpl["title"],
					"description": tpl["description"],
					"source_ip":   tpl["source_ip"],
					"entity_id":   tpl["entity_id"],
					"status":      "open",
					"timestamp":   time.Now().Format(time.RFC3339),
				},
			}
			h.broadcastIfConnected(msg)
		}
	}
}
