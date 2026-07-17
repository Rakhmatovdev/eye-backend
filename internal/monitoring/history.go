package monitoring

import "sync"

// SampleInterval and HistoryCapacity define the ring buffer sampling policy:
// a snapshot roughly every 15s, keeping the last ~240 samples (~1 hour).
const (
	SampleInterval  = 15 // seconds; used by the caller (main.go) to build the ticker
	HistoryCapacity = 240
)

// History is a simple in-memory ring buffer of MetricResponse snapshots.
// Single-instance only, like the login lockout tracker in pkg/middleware —
// there is no shared store for a multi-replica deployment.
type History struct {
	mu       sync.Mutex
	samples  []MetricResponse
	capacity int
}

// NewHistory creates a ring buffer with the given capacity. A capacity <= 0
// falls back to HistoryCapacity.
func NewHistory(capacity int) *History {
	if capacity <= 0 {
		capacity = HistoryCapacity
	}
	return &History{
		samples:  make([]MetricResponse, 0, capacity),
		capacity: capacity,
	}
}

// Add appends a sample, evicting the oldest sample once at capacity.
func (h *History) Add(m MetricResponse) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.samples) >= h.capacity {
		// Drop the oldest sample (index 0), shift the rest left.
		h.samples = append(h.samples[:0], h.samples[1:]...)
	}
	h.samples = append(h.samples, m)
}

// Snapshot returns a copy of the buffered samples, oldest-first.
func (h *History) Snapshot() []MetricResponse {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make([]MetricResponse, len(h.samples))
	copy(out, h.samples)
	return out
}

// Len returns the current number of buffered samples.
func (h *History) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.samples)
}
