package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteTextSortedReport(t *testing.T) {
	var output bytes.Buffer
	report := Aggregate([]Repository{{
		ID: "id", Path: "/repo", Status: StatusCompleted,
		Findings: []Finding{{Severity: SeverityError, Rule: "RULE", Path: "A.java", Message: "broken"}},
	}})
	if err := WriteText(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Repositories: 1 (completed: 1, failed: 0)",
		"Findings: 1 (error: 1, warning: 0, info: 0, unknown: 0)",
		"[completed] /repo (1 findings)",
		"ERROR  RULE  A.java  broken",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, output.String())
		}
	}
}

func TestAggregateUsesEmptyFindingArrays(t *testing.T) {
	report := Aggregate([]Repository{{ID: "id", Path: "/repo", Status: StatusCompleted}})
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"findings":null`) {
		t.Fatalf("findings must be an array: %s", encoded)
	}
}

func TestWriteTextEscapesTerminalControls(t *testing.T) {
	var output bytes.Buffer
	value := Aggregate([]Repository{{
		ID:     "id",
		Path:   "/repo\x1b]8;;https://evil.invalid\a\nforged",
		Status: StatusCompleted,
		Findings: []Finding{{
			Severity: SeverityWarning,
			Rule:     "RULE\tX",
			Path:     "A.java\rB.java",
			Message:  "bad\u0085line",
		}},
	}})
	if err := WriteText(&output, value); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, control := range []byte{0x1b, 0x07, '\r', '\t', 0x85} {
		if bytes.ContainsRune(output.Bytes(), rune(control)) {
			t.Fatalf("raw control byte %#x remains in %q", control, text)
		}
	}
	if strings.Count(text, "\n") != 5 {
		t.Fatalf("injected newline changed report structure: %q", text)
	}
	for _, escaped := range []string{`\x1b`, `\a`, `\n`, `\t`, `\r`, `\u0085`} {
		if !strings.Contains(text, escaped) {
			t.Fatalf("missing visible escape %q in %q", escaped, text)
		}
	}
}

func TestWriteJSONOmitsOpaqueDuplicatePayloads(t *testing.T) {
	value := Aggregate([]Repository{{
		ID:     "id",
		Path:   "/repo",
		Status: StatusCompleted,
		Result: json.RawMessage(`{"findings":[{"severity":"ERROR","ruleId":"RULE"}]}`),
	}})
	var output bytes.Buffer
	if err := WriteJSON(&output, value); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), `"result"`) || strings.Contains(output.String(), `"raw"`) {
		t.Fatalf("public JSON duplicates opaque analyzer payloads: %s", output.String())
	}
	if !strings.Contains(output.String(), `"rule": "RULE"`) {
		t.Fatalf("normalized finding missing: %s", output.String())
	}
}
