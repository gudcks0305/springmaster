package report

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAggregateExtractsWorkerResultAndSorts(t *testing.T) {
	report := Aggregate([]Repository{
		{
			ID:     "z",
			Path:   "/work/z",
			Status: StatusCompleted,
			Result: json.RawMessage(`{"findings":[{"severity":"warning","ruleId":"B","sourceFile":"z/B.java"},{"severity":"ERROR","ruleId":"A","primaryLocation":{"path":"a/A.java"}}]}`),
		},
		{ID: "a", Path: "/work/a", Status: StatusFailed, Error: "worker stopped"},
	})

	if got, want := report.Summary, (Summary{Repositories: 2, Completed: 1, Failed: 1, Findings: Counts{Total: 2, Errors: 1, Warnings: 1}}); !reflect.DeepEqual(got, want) {
		t.Fatalf("summary = %#v, want %#v", got, want)
	}
	if got, want := report.Repositories[0].ID, "a"; got != want {
		t.Fatalf("first repository = %q, want %q", got, want)
	}
	findings := report.Repositories[1].Findings
	if got, want := findings[0].Rule, "A"; got != want {
		t.Fatalf("first finding rule = %q, want %q", got, want)
	}
	if got, want := findings[0].Path, "a/A.java"; got != want {
		t.Fatalf("first finding path = %q, want %q", got, want)
	}
	if !report.MeetsThreshold(SeverityWarning) || report.MeetsThreshold(SeverityNone) {
		t.Fatal("threshold evaluation wrong")
	}
}

func TestExtractFindingsSupportsNestedWorkerEnvelope(t *testing.T) {
	findings, err := ExtractFindings(json.RawMessage(`{"schemaVersion":1,"result":{"findings":[{"severity":"INFO","rule":{"id":"RULE"},"primaryLocation":{"sourceFile":"A.java"},"message":"m"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := findings, []Finding{{Severity: SeverityInfo, Rule: "RULE", Path: "A.java", Message: "m", Raw: json.RawMessage(`{"message":"m","primaryLocation":{"sourceFile":"A.java"},"rule":{"id":"RULE"},"severity":"INFO"}`)}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("findings = %#v, want %#v", got, want)
	}
}

func TestExtractFindingsRejectsMalformedJSON(t *testing.T) {
	if _, err := ExtractFindings(json.RawMessage(`{`)); err == nil {
		t.Fatal("expected malformed JSON error")
	}
}

func TestParseSeverity(t *testing.T) {
	for _, test := range []struct {
		input string
		want  Severity
	}{
		{"never", SeverityNone},
		{"warn", SeverityWarning},
		{"ERROR", SeverityError},
	} {
		got, err := ParseSeverity(test.input)
		if err != nil || got != test.want {
			t.Fatalf("ParseSeverity(%q) = %q, %v; want %q, nil", test.input, got, err, test.want)
		}
	}
	if _, err := ParseSeverity("bad"); err == nil {
		t.Fatal("expected invalid severity")
	}
}

func TestAggregateFiltersReservedDependencyContextFindings(t *testing.T) {
	contextRoot := "/private/tmp/springmaster-run-123/springmaster-abc/_springmaster_deps"
	report := Aggregate([]Repository{{
		ID:                    "service",
		Path:                  "/work/service",
		DependencyContextPath: contextRoot,
		Status:                StatusCompleted,
		Findings: []Finding{
			{Severity: SeverityError, Rule: "DIRECT", Path: "./_springmaster_deps\\library/src/Library.java"},
			{Severity: SeverityError, Rule: "ABS", Path: contextRoot + "/library/src/Library.java"},
			{
				Severity: SeverityError,
				Rule:     "RAW",
				Path:     "src/main/java/Service.java",
				Raw:      json.RawMessage(`{"primaryLocation":{"path":"/private/tmp/springmaster-run-123/springmaster-abc/_springmaster_deps/library/src/Library.java"}}`),
			},
			{Severity: SeverityWarning, Rule: "SOURCE_NESTED", Path: "src/_springmaster_deps/Intentional.java"},
			{Severity: SeverityInfo, Rule: "SOURCE_ABS_NESTED", Path: "/work/service/src/_springmaster_deps/Intentional.java"},
		},
	}})

	findings := report.Repositories[0].Findings
	if got, want := len(findings), 2; got != want {
		t.Fatalf("public findings = %#v, want %d retained", findings, want)
	}
	if findings[0].Rule != "SOURCE_ABS_NESTED" || findings[1].Rule != "SOURCE_NESTED" {
		t.Fatalf("retained findings = %#v", findings)
	}
	if got, want := report.Summary.Findings, (Counts{Total: 2, Warnings: 1, Infos: 1}); !reflect.DeepEqual(got, want) {
		t.Fatalf("finding counts = %#v, want %#v", got, want)
	}
	if report.MeetsThreshold(SeverityError) {
		t.Fatal("private dependency-context errors must not trigger public threshold")
	}
}

func TestDependencyContextPathMappingIsExact(t *testing.T) {
	contextRoot := `C:\Temp\springmaster-run-1\springmaster-2\_springmaster_deps`
	for _, test := range []struct {
		name       string
		candidate  string
		repository string
		context    string
		want       bool
	}{
		{"relative root", `_springmaster_deps/library/A.java`, `/work/service`, "", true},
		{"relative nested source", `src/_springmaster_deps/A.java`, `/work/service`, "", false},
		{"original absolute root", `/work/service/_springmaster_deps/A.java`, `/work/service`, "", true},
		{"original absolute nested", `/work/service/src/_springmaster_deps/A.java`, `/work/service`, "", false},
		{"context root windows", `C:\Temp\springmaster-run-1\springmaster-2\_springmaster_deps\library\A.java`, `C:\work\service`, contextRoot, true},
		{"outside lookalike", `/other/source/_springmaster_deps/A.java`, `/work/service`, "", false},
		{"known private snapshot", `/private/tmp/springmaster-run-1/springmaster-2/_springmaster_deps/library/A.java`, `/work/service`, "", true},
		{"snapshot lookalike nested", `/private/tmp/springmaster-run-1/springmaster-2/src/_springmaster_deps/A.java`, `/work/service`, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isDependencyContextPath(test.candidate, test.repository, test.context); got != test.want {
				t.Fatalf("isDependencyContextPath(%q) = %t, want %t", test.candidate, got, test.want)
			}
		})
	}
}
