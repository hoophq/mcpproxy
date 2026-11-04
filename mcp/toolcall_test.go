package mcp

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode"
)

func TestParseToolCallReadsExactKeys(t *testing.T) {
	p, err := ParseToolCall(json.RawMessage(`{"name":"read_file","arguments": {"path":"/a"},"_meta":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "read_file" || string(p.Arguments) != `{"path":"/a"}` {
		t.Fatalf("got %q %s", p.Name, p.Arguments)
	}
	p, err = ParseToolCall(json.RawMessage(`{"name":"ping"}`))
	if err != nil || p.Name != "ping" || p.Arguments != nil {
		t.Fatalf("no arguments: %+v %v", p, err)
	}
	args := `{"s":"a,b\"}{,\\","n":[1,{"k":","}]}`
	p, err = ParseToolCall(json.RawMessage(`{ "name" : "x" , "arguments":` + args + `,"k":"\",\"name\":1"}`))
	if err != nil || p.Name != "x" || string(p.Arguments) != args {
		t.Fatalf("punctuation in strings: %+v %v", p, err)
	}
}

func TestParseToolCallRefusesAmbiguousParams(t *testing.T) {
	for _, params := range []string{
		`{"name":"delete_all","Name":"read_file"}`,
		`{"Name":"read_file","name":"delete_all"}`,
		`{"name":"read_file","name":"delete_all"}`,
		`{"name":"read_file","arguments":{"a":",}"},"name":"delete_all"}`,
		`{"Name":"read_file"}`,
		`{"NAME":"read_file","arguments":{}}`,
		`{"name":"x","arguments":{"a":1},"argumentſ":{"a":2}}`,
		`{"name":"x","ARGUMENTS":{"a":2}}`,
		`{"name":"x","Key":1,"key":2}`,
		`{"name":7}`,
		`{"name":""}`,
		`{"arguments":{}}`,
		`[]`,
		`null`,
		``,
	} {
		if p, err := ParseToolCall(json.RawMessage(params)); err == nil {
			t.Errorf("%s: accepted as %+v", params, p)
		}
	}
}

func TestFoldKeyAgreesWithEqualFold(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if foldKey(string(r)) != foldKey(string(f)) {
				t.Fatalf("%U and %U fold together but foldKey differs", r, f)
			}
		}
	}
	for _, c := range [][2]string{{"arguments", "argumentſ"}, {"kind", "Kind"}, {"name", "NAME"}, {"name", "names"}, {"ß", "ss"}} {
		if (foldKey(c[0]) == foldKey(c[1])) != strings.EqualFold(c[0], c[1]) {
			t.Errorf("%q, %q: foldKey and EqualFold disagree", c[0], c[1])
		}
	}
}
