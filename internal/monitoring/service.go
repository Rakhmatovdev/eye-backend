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

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}
