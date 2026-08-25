// Package report turns per-repository analyzer responses into one deterministic
// scan report. It deliberately depends only on the worker JSON contract, so a
// worker can add fields without forcing a CLI release.
package report

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"
)

// Severity is the normalized severity emitted by the analyzer.
type Severity string

const (
	SeverityNone    Severity = "NONE"
	SeverityInfo    Severity = "INFO"
	SeverityWarning Severity = "WARNING"
	SeverityError   Severity = "ERROR"
	SeverityUnknown Severity = "UNKNOWN"
)

// Finding is the small, stable subset of an analyzer finding needed by the
// aggregate scan report. Raw is retained only for internal processing; public
// JSON emits the normalized fields once.
type Finding struct {
	Severity Severity        `json:"severity"`
	Rule     string          `json:"rule,omitempty"`
	Path     string          `json:"path,omitempty"`
	Message  string          `json:"message,omitempty"`
	Raw      json.RawMessage `json:"-"`
}

// RepositoryStatus is the result of one repository analysis.
type RepositoryStatus string

const (
	StatusCompleted RepositoryStatus = "completed"
	StatusFailed    RepositoryStatus = "failed"
)

// Repository holds one repository result. Result is the worker's internal
// opaque payload used for extraction/cache handoff; public JSON omits it.
type Repository struct {
	ID                    string           `json:"id"`
	Path                  string           `json:"path"`
	Branch                string           `json:"branch,omitempty"`
	Head                  string           `json:"head,omitempty"`
	RemoteURL             string           `json:"remoteUrl,omitempty"`
	Status                RepositoryStatus `json:"status"`
	Error                 string           `json:"error,omitempty"`
	Result                json.RawMessage  `json:"-"`
	Findings              []Finding        `json:"findings"`
	CacheWarning          string           `json:"-"`
	DependencyContextPath string           `json:"-"`
}

// Counts contains finding totals without a map, keeping text and JSON output
// predictable across Go versions.
type Counts struct {
	Total    int `json:"total"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Infos    int `json:"infos"`
	Unknown  int `json:"unknown"`
}

// Summary is the aggregate scan status.
type Summary struct {
	Repositories int    `json:"repositories"`
	Completed    int    `json:"completed"`
	Failed       int    `json:"failed"`
	Findings     Counts `json:"findings"`
}

// Report is a sorted collection of isolated repository results.
type Report struct {
	Repositories []Repository `json:"repositories"`
	Summary      Summary      `json:"summary"`
}

// Aggregate normalizes findings, then sorts every externally visible list.
// A malformed result does not change a completed repository into a failed one:
// callers own that operational decision. Its findings are left empty.
func Aggregate(repositories []Repository) Report {
	items := make([]Repository, len(repositories))
	copy(items, repositories)

	for i := range items {
		items[i].Result = cloneRaw(items[i].Result)
		items[i].Findings = cloneFindings(items[i].Findings)
		if len(items[i].Findings) == 0 && len(items[i].Result) > 0 {
			findings, err := ExtractFindings(items[i].Result)
			if err == nil {
				items[i].Findings = findings
			}
		}
		if items[i].Findings == nil {
			items[i].Findings = []Finding{}
		}
		items[i].Findings = filterDependencyContextFindings(
			items[i].Findings,
			items[i].Path,
			items[i].DependencyContextPath,
		)
		sortFindings(items[i].Findings)
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		return items[i].ID < items[j].ID
	})

	result := Report{Repositories: items}
	result.Summary.Repositories = len(items)
	for _, repository := range items {
		if repository.Status == StatusFailed {
			result.Summary.Failed++
		} else {
			result.Summary.Completed++
		}
		for _, finding := range repository.Findings {
			increment(&result.Summary.Findings, finding.Severity)
		}
	}
	return result
}

// ParseSeverity parses both CLI threshold spelling and common analyzer values.
func ParseSeverity(value string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "", "NONE", "NEVER":
		return SeverityNone, nil
	case "INFO":
		return SeverityInfo, nil
	case "WARNING", "WARN":
		return SeverityWarning, nil
	case "ERROR", "ERR":
		return SeverityError, nil
	default:
		return SeverityUnknown, fmt.Errorf("invalid severity %q (want none, info, warning, or error)", value)
	}
}

// MeetsThreshold reports whether any known finding has at least threshold.
func (r Report) MeetsThreshold(threshold Severity) bool {
	if threshold == SeverityNone {
		return false
	}
	minimum := severityRank(threshold)
	if minimum < 0 {
		return false
	}
	for _, repository := range r.Repositories {
		for _, finding := range repository.Findings {
			if severityRank(finding.Severity) >= minimum {
				return true
			}
		}
	}
	return false
}

// ExtractFindings extracts the current analyzer shape (findings) and the
// JSONL worker shape (result.findings). Unknown fields are intentionally kept
// opaque. Empty result means no findings; malformed non-empty result is an
// error so callers can decide whether it is operational failure.
func ExtractFindings(raw json.RawMessage) ([]Finding, error) {
	if len(strings.TrimSpace(string(raw))) == 0 || string(raw) == "null" {
		return nil, nil
	}

	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("decode analyzer result: %w", err)
	}

	items := findingsValue(value)
	if items == nil {
		return nil, nil
	}

	findings := make([]Finding, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		encoded, err := json.Marshal(object)
		if err != nil {
			return nil, fmt.Errorf("encode analyzer finding: %w", err)
		}
		findings = append(findings, Finding{
			Severity: normalizeSeverity(stringAt(object, "severity", "level")),
			Rule:     firstNonEmpty(stringAt(object, "ruleId", "rule", "ruleID"), nestedString(object, "rule", "id")),
			Path:     findingPath(object),
			Message:  stringAt(object, "message", "title", "description"),
			Raw:      encoded,
		})
	}
	return findings, nil
}

func findingsValue(value any) []any {
	if values, ok := value.([]any); ok {
		return values
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if values, ok := object["findings"].([]any); ok {
		return values
	}
	if result, ok := object["result"]; ok {
		return findingsValue(result)
	}
	return nil
}

func findingPath(object map[string]any) string {
	return firstNonEmpty(
		stringAt(object, "sourceFile", "path", "location", "file"),
		nestedString(object, "primaryLocation", "sourceFile"),
		nestedString(object, "primaryLocation", "path"),
		nestedString(object, "primaryLocation", "file"),
	)
}

func nestedString(object map[string]any, key, nested string) string {
	child, ok := object[key].(map[string]any)
	if !ok {
		return ""
	}
	return stringAt(child, nested)
}

func stringAt(object map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := object[key].(string); ok {
			return value
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func normalizeSeverity(value string) Severity {
	severity, err := ParseSeverity(value)
	if err != nil || severity == SeverityNone {
		return SeverityUnknown
	}
	return severity
}

func increment(counts *Counts, severity Severity) {
	counts.Total++
	switch severity {
	case SeverityError:
		counts.Errors++
	case SeverityWarning:
		counts.Warnings++
	case SeverityInfo:
		counts.Infos++
	default:
		counts.Unknown++
	}
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityInfo:
		return 1
	case SeverityWarning:
		return 2
	case SeverityError:
		return 3
	default:
		return -1
	}
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.Rule != right.Rule {
			return left.Rule < right.Rule
		}
		if left.Message != right.Message {
			return left.Message < right.Message
		}
		return severityRank(left.Severity) > severityRank(right.Severity)
	})
}

func cloneFindings(findings []Finding) []Finding {
	if findings == nil {
		return nil
	}
	clone := make([]Finding, len(findings))
	copy(clone, findings)
	for i := range clone {
		clone[i].Raw = cloneRaw(clone[i].Raw)
	}
	return clone
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	if raw == nil {
		return nil
	}
	clone := make(json.RawMessage, len(raw))
	copy(clone, raw)
	return clone
}

const dependencyContextDirectory = "_springmaster_deps"

// filterDependencyContextFindings removes private overlay findings before a
// repository becomes public report data. The overlay improves analysis context
// only; it is never source owned by the repository being reported.
func filterDependencyContextFindings(findings []Finding, repositoryPath, contextPath string) []Finding {
	kept := findings[:0]
	for _, finding := range findings {
		if isDependencyContextFinding(finding, repositoryPath, contextPath) {
			continue
		}
		kept = append(kept, finding)
	}
	return kept
}

func isDependencyContextFinding(finding Finding, repositoryPath, contextPath string) bool {
	if isDependencyContextPath(finding.Path, repositoryPath, contextPath) {
		return true
	}
	if len(finding.Raw) == 0 {
		return false
	}

	var raw map[string]any
	if err := json.Unmarshal(finding.Raw, &raw); err != nil {
		return false
	}
	for _, candidate := range findingPathCandidates(raw) {
		if isDependencyContextPath(candidate, repositoryPath, contextPath) {
			return true
		}
	}
	return false
}

func findingPathCandidates(object map[string]any) []string {
	candidates := make([]string, 0, 7)
	appendCandidate := func(value string) {
		if value != "" {
			candidates = append(candidates, value)
		}
	}
	appendCandidate(stringAt(object, "sourceFile", "path", "location", "file"))
	for _, key := range []string{"primaryLocation", "location"} {
		child, ok := object[key].(map[string]any)
		if !ok {
			continue
		}
		appendCandidate(stringAt(child, "sourceFile", "path", "file", "location"))
	}
	return candidates
}

func isDependencyContextPath(candidate, repositoryPath, contextPath string) bool {
	normalized := normalizeReportPath(candidate)
	if normalized == "" || normalized == "." {
		return false
	}
	if !reportPathIsAbsolute(normalized) {
		return isReservedTopLevelPath(normalized)
	}

	if _, within := reportPathRelativeTo(contextPath, normalized); within {
		// ContextPath itself is the reserved directory, so every child is private.
		return true
	}
	if relative, within := reportPathRelativeTo(repositoryPath, normalized); within {
		return isReservedTopLevelPath(relative)
	}
	return isKnownSnapshotDependencyPath(normalized)
}

func normalizeReportPath(value string) string {
	if value == "" {
		return ""
	}
	normalized := strings.ReplaceAll(value, "\\", "/")
	volume, suffix := reportPathVolume(normalized)
	if suffix == "" {
		return ""
	}
	return volume + path.Clean(suffix)
}

func reportPathRelativeTo(root, candidate string) (string, bool) {
	normalizedRoot := normalizeReportPath(root)
	if normalizedRoot == "" || !reportPathIsAbsolute(normalizedRoot) || !reportPathIsAbsolute(candidate) {
		return "", false
	}
	rootVolume, rootSuffix := reportPathVolume(normalizedRoot)
	candidateVolume, candidateSuffix := reportPathVolume(candidate)
	if !strings.EqualFold(rootVolume, candidateVolume) {
		return "", false
	}
	comparisonRoot, comparisonCandidate := rootSuffix, candidateSuffix
	if rootVolume != "" {
		comparisonRoot = strings.ToLower(comparisonRoot)
		comparisonCandidate = strings.ToLower(comparisonCandidate)
	}
	if comparisonCandidate == comparisonRoot {
		return ".", true
	}
	prefix := strings.TrimSuffix(comparisonRoot, "/") + "/"
	if !strings.HasPrefix(comparisonCandidate, prefix) {
		return "", false
	}
	return candidateSuffix[len(prefix):], true
}

func reportPathVolume(value string) (string, string) {
	if len(value) >= 2 && value[1] == ':' && unicode.IsLetter(rune(value[0])) {
		return value[:2], value[2:]
	}
	return "", value
}

func reportPathIsAbsolute(value string) bool {
	_, suffix := reportPathVolume(value)
	return strings.HasPrefix(suffix, "/")
}

func isReservedTopLevelPath(value string) bool {
	return value == dependencyContextDirectory || strings.HasPrefix(value, dependencyContextDirectory+"/")
}

// isKnownSnapshotDependencyPath is a narrow fallback for callers that have
// not supplied DependencyContextPath. It recognizes only the coordinator's
// private run/snapshot layout, never a source path merely containing a
// similarly named directory.
func isKnownSnapshotDependencyPath(value string) bool {
	_, suffix := reportPathVolume(value)
	parts := strings.Split(strings.TrimPrefix(suffix, "/"), "/")
	for index := 2; index < len(parts); index++ {
		if parts[index] != dependencyContextDirectory {
			continue
		}
		if strings.HasPrefix(parts[index-1], "springmaster-") &&
			strings.HasPrefix(parts[index-2], "springmaster-run-") {
			return true
		}
	}
	return false
}
