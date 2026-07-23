package alerts

import "go.mongodb.org/mongo-driver/bson"

// resolveLabel picks a human-readable label from an entity's free-form
// properties map: "label" wins (set by entities.UpdateEntityRequest), then
// "name" (used by the seed data), then empty (caller falls back to the id).
func resolveLabel(props map[string]interface{}) string {
	if props == nil {
		return ""
	}
	if v, ok := props["label"].(string); ok && v != "" {
		return v
	}
	if v, ok := props["name"].(string); ok && v != "" {
		return v
	}
	return ""
}

// toFloat64 coerces a decoded BSON numeric (int32/int64/float64 — the driver
// picks the concrete type based on how the value was stored) into a float64.
// ok is false when v is nil or not a recognizable numeric type.
func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

// toStringSlice coerces a decoded array into a []string, dropping any
// non-string elements. AlertRule.Params is a free-form map[string]interface{},
// so an array value may come back as bson.A (BSON-decoded, from Mongo) or as
// []interface{} (JSON-decoded, from a request body) depending on the path —
// both are handled.
func toStringSlice(v interface{}) []string {
	var arr []interface{}
	switch t := v.(type) {
	case bson.A:
		arr = t
	case []interface{}:
		arr = t
	default:
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
