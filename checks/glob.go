package checks

// Match reports whether name matches pattern. The only metacharacter is "*",
// which matches any run of characters including the empty run; every other
// byte must match literally. Matching is case-sensitive because MCP tool
// names are case-sensitive identifiers. A case-insensitive matcher would let
// "Read_File" slip past a "read_file" deny rule.
func Match(pattern, name string) bool {
	// Two-pointer scan with backtracking to the most recent '*'. Linear in
	// the common case, no allocation, no regexp compilation per message.
	p, n := 0, 0
	star, starNext := -1, 0
	for n < len(name) {
		switch {
		case p < len(pattern) && pattern[p] == name[n]:
			p++
			n++
		case p < len(pattern) && pattern[p] == '*':
			star, starNext = p, n
			p++
		case star >= 0:
			// Backtrack: let the last '*' swallow one more byte.
			starNext++
			p, n = star+1, starNext
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// MatchAny reports whether name matches at least one pattern.
func MatchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if Match(p, name) {
			return true
		}
	}
	return false
}
