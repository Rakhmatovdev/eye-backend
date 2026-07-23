package entities

import (
	"reflect"
	"testing"
)

func rel(from, to string) *Relationship {
	return &Relationship{EntityIDFrom: from, EntityIDTo: to}
}

func TestCommonNeighborIDs(t *testing.T) {
	// a-x, a-y, b-y, b-z: only y is a common neighbor of a and b.
	rels := []*Relationship{
		rel("a", "x"),
		rel("a", "y"),
		rel("y", "b"), // direction reversed on purpose — must still count
		rel("b", "z"),
	}

	got := CommonNeighborIDs(rels, "a", "b")
	want := []string{"y"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestCommonNeighborIDs_ExcludesEndpointsThemselves(t *testing.T) {
	// a and b are directly connected to each other, plus both connect to c.
	rels := []*Relationship{
		rel("a", "b"),
		rel("a", "c"),
		rel("b", "c"),
	}
	got := CommonNeighborIDs(rels, "a", "b")
	want := []string{"c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v (a and b must not appear even though they're mutually connected), got %v", want, got)
	}
}

func TestCommonNeighborIDs_NoOverlap(t *testing.T) {
	rels := []*Relationship{rel("a", "x"), rel("b", "y")}
	got := CommonNeighborIDs(rels, "a", "b")
	if len(got) != 0 {
		t.Fatalf("expected no common neighbors, got %v", got)
	}
}

func TestDegreeCounts(t *testing.T) {
	rels := []*Relationship{
		rel("a", "b"),
		rel("a", "c"),
		rel("c", "b"),
	}
	got := DegreeCounts(rels)
	want := map[string]int{"a": 2, "b": 2, "c": 2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestTopDegrees(t *testing.T) {
	degrees := map[string]int{"a": 5, "b": 9, "c": 1, "d": 9}
	top := topDegrees(degrees, 2)
	if len(top) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(top))
	}
	// b and d tie at 9; alphabetical tiebreak puts b before d.
	if top[0].ID != "b" || top[0].Degree != 9 {
		t.Fatalf("expected b first, got %+v", top[0])
	}
	if top[1].ID != "d" || top[1].Degree != 9 {
		t.Fatalf("expected d second, got %+v", top[1])
	}
}
