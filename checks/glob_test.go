package checks

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"read_file", "read_file", true},
		{"read_file", "read_files", false},
		{"read_file", "Read_File", false}, // case-sensitive
		{"*", "anything", true},
		{"*", "", true},
		{"", "", true},
		{"", "x", false},
		{"read_*", "read_file", true},
		{"read_*", "read_", true},
		{"read_*", "write_file", false},
		{"*_file", "read_file", true},
		{"*_file", "file", false},
		{"*file*", "my_file_here", true},
		{"a*b*c", "abc", true},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXcYYb", false},
		{"**", "abc", true},
		// Backtracking: the greedy first star must give bytes back.
		{"*a*b", "xxaxxb", true},
		{"*ab", "aab", true},
		{"*ab", "aba", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.name); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestMatchAny(t *testing.T) {
	pats := []string{"admin_*", "delete_file"}
	if !MatchAny(pats, "admin_reset") {
		t.Error("admin_reset should match admin_*")
	}
	if !MatchAny(pats, "delete_file") {
		t.Error("delete_file should match its literal")
	}
	if MatchAny(pats, "read_file") {
		t.Error("read_file should not match")
	}
	if MatchAny(nil, "anything") {
		t.Error("empty pattern set must match nothing")
	}
}
