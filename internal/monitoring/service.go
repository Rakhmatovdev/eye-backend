package monitoring

import (
	"runtime"
	"time"
)

var startTime = time.Now()

type Service struct{}

func NewService() *Service {
	return &Service{}
}

type MetricResponse struct {
	// Real process/runtime metrics (not synthetic).
	HeapAllocMB   float64   `json:"heap_alloc_mb"`
	SysMemMB      float64   `json:"sys_mem_mb"`
	MemoryUsage   float64   `json:"memory_usage"` // heap as % of reserved sys, for gauge widgets
	Goroutines    int       `json:"goroutines"`
	NumGC         uint32    `json:"num_gc"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	NumCPU        int       `json:"num_cpu"`
	Timestamp     time.Time `json:"timestamp"`
}

type ServiceStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"` // up, degraded, down
}

func (s *Service) GetMetrics() MetricResponse {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	const mb = 1024 * 1024
	heapMB := float64(m.HeapAlloc) / mb
	sysMB := float64(m.Sys) / mb
	memPct := 0.0
	if sysMB > 0 {
		memPct = heapMB / sysMB * 100
	}

	return MetricResponse{
		HeapAllocMB:   round2(heapMB),
		SysMemMB:      round2(sysMB),
		MemoryUsage:   round2(memPct),
		Goroutines:    runtime.NumGoroutine(),
		NumGC:         m.NumGC,
		UptimeSeconds: int64(time.Since(startTime).Seconds()),
		NumCPU:        runtime.NumCPU(),
		Timestamp:     time.Now(),
	}
}

func (s *Service) GetServiceStatus() []ServiceStatus {
	return []ServiceStatus{
		{Name: "MongoDB Atlas", Status: "up"},
		{Name: "API Gateway", Status: "up"},
		{Name: "WebSocket Server", Status: "up"},
		{Name: "SIEM Threat Engine", Status: "up"},
		{Name: "Ingest Pipeline", Status: "up"},
		{Name: "mTLS Agent Controller", Status: "up"},
	}
}

// DataSource describes an integrated data source feeding the platform. The list
// reflects the REAL current architecture (MongoDB Atlas, the sensor grid, the
// live WebSocket channel, SIEM ingest, audit store) rather than legacy demo data.
type DataSource struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`   // mongodb, api, kafka, elasticsearch, s3, csv
	Status       string   `json:"status"` // connected, syncing, warning, error
	Host         string   `json:"host"`
	Database     string   `json:"database"`
	RecordCount  int64    `json:"record_count"`
	SyncInterval int      `json:"sync_interval"`
	Description  string   `json:"description"`
	Tags         []string `json:"tags"`
	ErrorMessage string   `json:"error_message,omitempty"`
}

func (s *Service) GetDataSources() []DataSource {
	return []DataSource{
		{ID: "ds-mongo", Name: "MongoDB Atlas (primary)", Type: "mongodb", Status: "connected", Host: "cluster.9k6wwcl.mongodb.net", Database: "intelligence_db", RecordCount: 12483, SyncInterval: 30, Description: "Primary datastore — users, entities, cases, security and COP collections", Tags: []string{"core", "primary"}},
		{ID: "ds-sensors", Name: "Surveillance Sensor Grid", Type: "api", Status: "connected", Host: "sim://sensor-grid", Database: "detections", RecordCount: 16, SyncInterval: 5, Description: "Cameras, drones, radar and SIGINT collectors feeding entity detections", Tags: []string{"sensors", "realtime"}},
		{ID: "ds-ws", Name: "Live Threat WebSocket", Type: "kafka", Status: "connected", Host: "ws://backend:8080/ws", Database: "live-frames", RecordCount: 0, SyncInterval: 0, Description: "Real-time detection/threat broadcast channel", Tags: []string{"realtime", "stream"}},
		{ID: "ds-siem", Name: "SIEM / Security Ingest", Type: "elasticsearch", Status: "connected", Host: "siem.internal", Database: "security_incidents", RecordCount: 11, SyncInterval: 60, Description: "Security incidents, vulnerabilities and blocklist ingest", Tags: []string{"security", "siem"}},
		{ID: "ds-audit", Name: "Audit Log Store", Type: "mongodb", Status: "connected", Host: "cluster.9k6wwcl.mongodb.net", Database: "audit_logs", RecordCount: 0, SyncInterval: 0, Description: "Tamper-evident hash-chained audit trail", Tags: []string{"audit", "compliance"}},
		{ID: "ds-sigint", Name: "SIGINT Collector Feed", Type: "kafka", Status: "syncing", Host: "sigint-relay.internal", Database: "comint", RecordCount: 0, SyncInterval: 0, Description: "Signals-intelligence intercept stream (COMINT)", Tags: []string{"sigint", "streaming"}},
		{ID: "ds-osint", Name: "External OSINT API", Type: "api", Status: "warning", Host: "api.osint-provider.example", Database: "", RecordCount: 145823, SyncInterval: 3600, Description: "Open-source intelligence enrichment feed", Tags: []string{"osint", "external"}, ErrorMessage: "Rate limit at 80% — throttling imminent"},
	}
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}
