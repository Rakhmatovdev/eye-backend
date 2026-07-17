package pagination

import "testing"

func TestParseBothAbsent(t *testing.T) {
	_, ok := Parse("", "")
	if ok {
		t.Fatal("expected ok=false when both page and limit are absent")
	}
}

func TestParsePageOnly(t *testing.T) {
	p, ok := Parse("3", "")
	if !ok {
		t.Fatal("expected ok=true when page is present")
	}
	if p.Page != 3 {
		t.Fatalf("expected page 3, got %d", p.Page)
	}
	if p.Limit != DefaultLimit {
		t.Fatalf("expected default limit %d, got %d", DefaultLimit, p.Limit)
	}
}

func TestParseLimitOnly(t *testing.T) {
	p, ok := Parse("", "50")
	if !ok {
		t.Fatal("expected ok=true when limit is present")
	}
	if p.Page != 1 {
		t.Fatalf("expected default page 1, got %d", p.Page)
	}
	if p.Limit != 50 {
		t.Fatalf("expected limit 50, got %d", p.Limit)
	}
}

func TestParseClampsInvalidAndOutOfRangeValues(t *testing.T) {
	cases := []struct {
		name        string
		page, limit string
		wantPage    int
		wantLimit   int
	}{
		{"negative page", "-5", "10", 1, 10},
		{"zero page", "0", "10", 1, 10},
		{"non-numeric page", "abc", "10", 1, 10},
		{"non-numeric limit", "1", "xyz", 1, DefaultLimit},
		{"limit over max clamps", "1", "9999", 1, MaxLimit},
		{"negative limit", "1", "-1", 1, DefaultLimit},
		{"zero limit", "1", "0", 1, DefaultLimit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := Parse(tc.page, tc.limit)
			if !ok {
				t.Fatal("expected ok=true")
			}
			if p.Page != tc.wantPage {
				t.Fatalf("expected page %d, got %d", tc.wantPage, p.Page)
			}
			if p.Limit != tc.wantLimit {
				t.Fatalf("expected limit %d, got %d", tc.wantLimit, p.Limit)
			}
		})
	}
}

func TestSkipAndTake(t *testing.T) {
	p := Params{Page: 3, Limit: 20}
	if p.Skip() != 40 {
		t.Fatalf("expected skip 40, got %d", p.Skip())
	}
	if p.Take() != 20 {
		t.Fatalf("expected take 20, got %d", p.Take())
	}
}

func TestToMeta(t *testing.T) {
	p := Params{Page: 2, Limit: 10}
	m := p.ToMeta(35)
	if m.Page != 2 || m.Limit != 10 || m.Total != 35 {
		t.Fatalf("unexpected meta: %+v", m)
	}
}
