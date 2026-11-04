package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

var (
	foldedName      = foldKey("name")
	foldedArguments = foldKey("arguments")
)

// ParseToolCall reads a tools/call's name and arguments by their exact keys,
// as an MCP server does. Go's JSON decoder matches keys without case, so it
// refuses params with two keys equal under strings.EqualFold, or a key that
// only folds to "name" or "arguments": a check would judge one value and the
// server run another.
func ParseToolCall(params json.RawMessage) (ToolsCallParams, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(params, &fields); err != nil || fields == nil {
		return ToolsCallParams{}, errors.New("params are not an object")
	}
	if members(params) != len(fields) {
		return ToolsCallParams{}, errors.New("params repeat a key")
	}
	seen := make(map[string]string, len(fields))
	for key := range fields {
		f := foldKey(key)
		if prev, dup := seen[f]; dup {
			return ToolsCallParams{}, fmt.Errorf("keys %q and %q are equal without case", prev, key)
		}
		seen[f] = key
		switch {
		case f == foldedName && key != "name":
			return ToolsCallParams{}, fmt.Errorf("key %q is not %q", key, "name")
		case f == foldedArguments && key != "arguments":
			return ToolsCallParams{}, fmt.Errorf("key %q is not %q", key, "arguments")
		}
	}
	var p ToolsCallParams
	if err := json.Unmarshal(fields["name"], &p.Name); err != nil || p.Name == "" {
		return ToolsCallParams{}, errors.New("a tool name is required")
	}
	p.Arguments = fields["arguments"]
	return p, nil
}

// members counts the members of obj, a valid JSON object.
func members(obj []byte) int {
	n, depth := 0, 0
	inString, escaped := false, false
	for _, c := range obj {
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
			if depth == 1 && n == 0 {
				n = 1
			}
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		case ',':
			if depth == 1 {
				n++
			}
		}
	}
	return n
}

// foldKey maps s to one member of its case-fold class: two strings are equal
// under strings.EqualFold, as Go's JSON decoder matches keys, exactly when
// their foldKeys are equal.
func foldKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			low = min(low, f)
		}
		b.WriteRune(low)
	}
	return b.String()
}
