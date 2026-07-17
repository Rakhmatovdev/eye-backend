package monitoring

import "time"

// StartSampler periodically captures a metrics snapshot (the same snapshot
// GetMetrics produces) into hist, so GET /monitoring/metrics/history can
// serve a time series. Call once, in a goroutine, from cmd/api/main.go —
// mirrors how internal/realtime.StartBroadcaster is started there.
//
// The buffer is seeded with one sample immediately so the endpoint never
// returns empty right after boot.
func StartSampler(svc *Service, hist *History) {
	hist.Add(svc.GetMetrics())

	ticker := time.NewTicker(SampleInterval * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		hist.Add(svc.GetMetrics())
	}
}
