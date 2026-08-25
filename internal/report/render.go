package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// WriteText writes a concise, deterministic report suitable for terminals and
// CI logs. It never writes progress output; callers can reserve stderr for it.
func WriteText(output io.Writer, report Report) error {
	summary := report.Summary
	if _, err := fmt.Fprintf(output,
		"Repositories: %d (completed: %d, failed: %d)\nFindings: %d (error: %d, warning: %d, info: %d, unknown: %d)\n",
		summary.Repositories, summary.Completed, summary.Failed,
		summary.Findings.Total, summary.Findings.Errors, summary.Findings.Warnings,
		summary.Findings.Infos, summary.Findings.Unknown,
	); err != nil {
		return err
	}

	for _, repository := range report.Repositories {
		if repository.Status == StatusFailed {
			if _, err := fmt.Fprintf(output, "\n[%s] %s: %s\n", repository.Status, safeText(repository.Path), safeText(repository.Error)); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(output, "\n[%s] %s (%d findings)\n", repository.Status, safeText(repository.Path), len(repository.Findings)); err != nil {
			return err
		}
		for _, finding := range repository.Findings {
			location := finding.Path
			if location == "" {
				location = "-"
			}
			if _, err := fmt.Fprintf(output, "  %s  %s  %s  %s\n", finding.Severity, safeText(finding.Rule), safeText(location), safeText(finding.Message)); err != nil {
				return err
			}
		}
	}
	return nil
}

// safeText makes every terminal-control byte visible. Backslashes are escaped
// too, so an injected newline cannot be confused with literal "\\n" text.
func safeText(value string) string {
	var output strings.Builder
	output.Grow(len(value))
	for _, character := range value {
		switch character {
		case '\\':
			output.WriteString(`\\`)
		case '\n':
			output.WriteString(`\n`)
		case '\r':
			output.WriteString(`\r`)
		case '\t':
			output.WriteString(`\t`)
		case '\b':
			output.WriteString(`\b`)
		case '\f':
			output.WriteString(`\f`)
		case '\v':
			output.WriteString(`\v`)
		default:
			if character < 0x20 || character >= 0x7f && character <= 0x9f {
				quoted := strconv.QuoteRuneToASCII(character)
				output.WriteString(quoted[1 : len(quoted)-1])
			} else {
				output.WriteRune(character)
			}
		}
	}
	return output.String()
}

// WriteJSON writes one report JSON document. Encoder keeps the output valid
// even when a result contains arbitrary JSON fields.
func WriteJSON(output io.Writer, report Report) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
