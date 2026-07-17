package monitoring

import "testing"

func TestHistoryAppendAndOrder(t *testing.T) {
	h := NewHistory(3)

	for i := 0; i < 3; i++ {
		h.Add(MetricResponse{UptimeSeconds: int64(i)})
	}

	snap := h.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("expected 3 samples, got %d", len(snap))
	}
	for i, s := range snap {
		if s.UptimeSeconds != int64(i) {
			t.Fatalf("expected oldest-first order at index %d, got %d", i, s.UptimeSeconds)
		}
	}
}

func TestHistoryCapacityCap(t *testing.T) {
	h := NewHistory(3)

	for i := 0; i < 5; i++ {
		h.Add(MetricResponse{UptimeSeconds: int64(i)})
	}

	snap := h.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("expected capacity cap of 3, got %d", len(snap))
	}
	// The two oldest samples (0, 1) should have been evicted; remaining
	// samples must still be oldest-first.
	want := []int64{2, 3, 4}
	for i, s := range snap {
		if s.UptimeSeconds != want[i] {
			t.Fatalf("index %d: expected %d, got %d", i, want[i], s.UptimeSeconds)
		}
	}
}

func TestHistoryDefaultCapacity(t *testing.T) {
	h := NewHistory(0)
	if h.capacity != HistoryCapacity {
		t.Fatalf("expected default capacity %d, got %d", HistoryCapacity, h.capacity)
	}

	hNeg := NewHistory(-5)
	if hNeg.capacity != HistoryCapacity {
		t.Fatalf("expected default capacity for negative input, got %d", hNeg.capacity)
	}
}

func TestHistorySnapshotIsACopy(t *testing.T) {
	h := NewHistory(2)
	h.Add(MetricResponse{UptimeSeconds: 1})

	snap := h.Snapshot()
	snap[0].UptimeSeconds = 999

	snap2 := h.Snapshot()
	if snap2[0].UptimeSeconds != 1 {
		t.Fatal("mutating a snapshot must not affect the underlying buffer")
	}
}

func TestHistoryLen(t *testing.T) {
	h := NewHistory(2)
	if h.Len() != 0 {
		t.Fatalf("expected empty buffer, got len %d", h.Len())
	}
	h.Add(MetricResponse{})
	h.Add(MetricResponse{})
	h.Add(MetricResponse{})
	if h.Len() != 2 {
		t.Fatalf("expected len capped at 2, got %d", h.Len())
	}
}
