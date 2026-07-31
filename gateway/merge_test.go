package gateway

import (
	"encoding/json"
	"testing"
)

// mergeListFields is what keeps a newer revision's result fields alive across
// aggregation. The previous implementation rebuilt a typed result and so
// dropped every field the gateway does not model.
func TestMergeListFieldsPreservesUnmodelledFields(t *testing.T) {
	dst := map[string]json.RawMessage{}
	mergeListFields(dst, map[string]json.RawMessage{
		"tools":        json.RawMessage(`[{"name":"a"}]`),
		"nextCursor":   json.RawMessage(`"abc"`),
		"someNewField": json.RawMessage(`{"future":true}`),
	})
	if _, ok := dst["tools"]; ok {
		t.Error("tools must be rebuilt by the caller, not merged")
	}
	if _, ok := dst["nextCursor"]; ok {
		t.Error("a per-backend cursor is meaningless once catalogs are concatenated")
	}
	if string(dst["someNewField"]) != `{"future":true}` {
		t.Errorf("unmodelled field dropped: %s", dst["someNewField"])
	}
}

// A merged catalog is only as fresh as its stalest contributor.
func TestMergeListFieldsTakesMinimumTTL(t *testing.T) {
	dst := map[string]json.RawMessage{}
	mergeListFields(dst, map[string]json.RawMessage{"ttlMs": json.RawMessage(`60000`)})
	mergeListFields(dst, map[string]json.RawMessage{"ttlMs": json.RawMessage(`5000`)})
	mergeListFields(dst, map[string]json.RawMessage{"ttlMs": json.RawMessage(`30000`)})
	if string(dst["ttlMs"]) != "5000" {
		t.Errorf("ttlMs = %s, want the minimum 5000", dst["ttlMs"])
	}
}

// A merged catalog is only as shareable as its most restrictive contributor:
// one permissive backend must not license a shared cache to serve another
// backend's private catalog.
func TestMergeListFieldsPrivateScopeWins(t *testing.T) {
	for _, order := range [][]string{
		{`"public"`, `"private"`},
		{`"private"`, `"public"`},
	} {
		dst := map[string]json.RawMessage{}
		for _, scope := range order {
			mergeListFields(dst, map[string]json.RawMessage{"cacheScope": json.RawMessage(scope)})
		}
		if string(dst["cacheScope"]) != `"private"` {
			t.Errorf("order %v: cacheScope = %s, want \"private\"", order, dst["cacheScope"])
		}
	}
}

// All-public contributors leave the result publicly cacheable.
func TestMergeListFieldsAllPublicStaysPublic(t *testing.T) {
	dst := map[string]json.RawMessage{}
	mergeListFields(dst, map[string]json.RawMessage{"cacheScope": json.RawMessage(`"public"`)})
	mergeListFields(dst, map[string]json.RawMessage{"cacheScope": json.RawMessage(`"public"`)})
	if string(dst["cacheScope"]) != `"public"` {
		t.Errorf("cacheScope = %s, want \"public\"", dst["cacheScope"])
	}
}

// A malformed hint must not clobber a good one.
func TestMergeListFieldsIgnoresMalformedHints(t *testing.T) {
	dst := map[string]json.RawMessage{}
	mergeListFields(dst, map[string]json.RawMessage{"ttlMs": json.RawMessage(`5000`)})
	mergeListFields(dst, map[string]json.RawMessage{"ttlMs": json.RawMessage(`"soon"`)})
	if string(dst["ttlMs"]) != "5000" {
		t.Errorf("ttlMs = %s, want the valid 5000 retained", dst["ttlMs"])
	}
}
