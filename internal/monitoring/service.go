package monitoring

import (
	"math/rand"
	"time"
)

type Service struct{}

func NewService() *Service {
	return &Service{}
}

type MetricResponse struct {
	CPUUsage    float64   `json:"cpu_usage"`
	MemoryUsage float64   `json:"memory_usage"`
	APIRequests int       `json:"api_requests"`
	ActiveConns int       `json:"active_connections"`
	Timestamp   time.Time `json:"timestamp"`
}

type ServiceStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"` // up, degraded, down
}

func (s *Service) GetMetrics() MetricResponse {
	return MetricResponse{
		CPUUsage:    rand.Float64()*40 + 10,
		MemoryUsage: rand.Float64()*30 + 40,
		APIRequests: rand.Intn(100) + 50,
		ActiveConns: rand.Intn(20) + 10,
		Timestamp:   time.Now(),
	}
}

func (s *Service) GetServiceStatus() []ServiceStatus {
	return []ServiceStatus{
		{Name: "PostgreSQL", Status: "up"},
		{Name: "Redis", Status: "up"},
		{Name: "WebSocket Server", Status: "up"},
		{Name: "SIEM Threat Engine", Status: "up"},
		{Name: "Ingest Pipeline", Status: "up"},
		{Name: "mTLS Agent Controller", Status: "up"},
	}
}
