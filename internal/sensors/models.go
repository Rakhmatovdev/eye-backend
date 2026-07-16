package sensors

import "time"

// Sensor is a surveillance asset in the collection network — a fixed camera, a
// drone/UAV, a radar, a SIGINT collector, etc. All data here is synthetic demo
// data (this is a Palantir-style simulation, not a real sensor integration).
type Sensor struct {
	ID             string    `json:"id" bson:"_id"`
	Name           string    `json:"name" bson:"name"`
	Type           string    `json:"type" bson:"type"`     // camera, drone, radar, sigint, thermal, motion
	Status         string    `json:"status" bson:"status"` // online, offline, degraded
	Lat            float64   `json:"lat" bson:"lat"`
	Lng            float64   `json:"lng" bson:"lng"`
	Area           string    `json:"area" bson:"area"`
	CoverageRadius int       `json:"coverage_radius" bson:"coverage_radius"` // meters
	Resolution     string    `json:"resolution" bson:"resolution"`
	Classification string    `json:"classification" bson:"classification"`
	FeedURL        string    `json:"feed_url" bson:"feed_url"` // simulated stream identifier
	LastHeartbeat  time.Time `json:"last_heartbeat" bson:"last_heartbeat"`
	CreatedAt      time.Time `json:"created_at" bson:"created_at"`
}

// Detection is a "hit" produced by a sensor — the moment a sensor identifies a
// tracked entity (face match, plate match) or picks up an unattributed signal.
// This is what powers "find a person": which sensor saw whom, where, when.
type Detection struct {
	ID         string    `json:"id" bson:"_id"`
	SensorID   string    `json:"sensor_id" bson:"sensor_id"`
	SensorName string    `json:"sensor_name" bson:"sensor_name"`
	EntityID   string    `json:"entity_id" bson:"entity_id"` // "" = unidentified
	EntityName string    `json:"entity_name" bson:"entity_name"`
	Kind       string    `json:"kind" bson:"kind"`             // face_match, plate_match, thermal, motion, signal
	Confidence float64   `json:"confidence" bson:"confidence"` // 0..1
	Lat        float64   `json:"lat" bson:"lat"`
	Lng        float64   `json:"lng" bson:"lng"`
	Area       string    `json:"area" bson:"area"`
	Timestamp  time.Time `json:"timestamp" bson:"timestamp"`
}

// SensorInput is the create/update payload for admin management of a sensor.
type SensorInput struct {
	Name           string  `json:"name" binding:"required"`
	Type           string  `json:"type" binding:"required"`
	Status         string  `json:"status"`
	Lat            float64 `json:"lat"`
	Lng            float64 `json:"lng"`
	Area           string  `json:"area"`
	CoverageRadius int     `json:"coverage_radius"`
	Resolution     string  `json:"resolution"`
	Classification string  `json:"classification"`
}

// Stats is an aggregate summary for the surveillance dashboard header.
type Stats struct {
	Total          int64 `json:"total"`
	Online         int64 `json:"online"`
	Degraded       int64 `json:"degraded"`
	Offline        int64 `json:"offline"`
	Detections24h  int64 `json:"detections_24h"`
	IdentifiedHits int64 `json:"identified_hits"`
}
