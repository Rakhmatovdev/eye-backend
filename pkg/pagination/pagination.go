// Package pagination provides a small, dependency-free helper for parsing
// `?page=&limit=` query parameters shared by every paginated list endpoint.
//
// Callers pass the raw page/limit query-string values (empty string if the
// parameter was not supplied). Parse reports ok=false only when BOTH values
// are empty — in that case the caller must preserve its pre-pagination
// behaviour (return everything, no `meta` in the response) so existing
// frontends that never send these params keep working unchanged. As soon as
// either value is present, pagination activates using sane defaults/clamps
// for whichever value is missing or invalid.
package pagination

import "strconv"

const (
	// DefaultLimit is used when limit is missing/invalid but page (or the
	// other way round) was supplied.
	DefaultLimit = 20
	// MaxLimit caps the page size to keep queries cheap.
	MaxLimit = 100
)

// Params holds parsed, clamped pagination values (1-based page).
type Params struct {
	Page  int
	Limit int
}

// Meta is the `meta` object returned alongside a paginated list.
type Meta struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
	Total int `json:"total"`
}

// Parse reads page/limit query-string values. ok is false only when both
// pageStr and limitStr are empty, meaning the caller received no pagination
// intent at all and should fall back to its old, unpaginated behaviour.
func Parse(pageStr, limitStr string) (Params, bool) {
	if pageStr == "" && limitStr == "" {
		return Params{}, false
	}

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	return Params{Page: page, Limit: limit}, true
}

// Skip returns the Mongo `skip` offset for these params.
func (p Params) Skip() int64 {
	return int64((p.Page - 1) * p.Limit)
}

// Take returns the Mongo `limit` value for these params.
func (p Params) Take() int64 {
	return int64(p.Limit)
}

// ToMeta builds the response meta object given a total document count.
func (p Params) ToMeta(total int64) Meta {
	return Meta{Page: p.Page, Limit: p.Limit, Total: int(total)}
}
