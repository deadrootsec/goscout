package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/deadrootsec/goscout/pkg/scanner"
	"github.com/fatih/color"
)

// Reporter handles generating reports in different formats
type Reporter struct {
	writer io.Writer
	format string
}

// JSONReport represents the JSON output format
type JSONReport struct {
	Summary *Summary       `json:"summary"`
	Matches []*MatchReport `json:"matches"`
	Stats   *Stats         `json:"stats"`
}

// MatchReport represents a match in the report
type MatchReport struct {
	FilePath    string `json:"file_path"`
	LineNumber  int    `json:"line_number"`
	PatternName string `json:"pattern_name"`
	Severity    string `json:"severity"`
	Match       string `json:"match"`
	LineContent string `json:"line_content"`
}

// Summary contains scan summary information
type Summary struct {
	TotalMatches   int `json:"total_matches"`
	HighSeverity   int `json:"high_severity"`
	MediumSeverity int `json:"medium_severity"`
	LowSeverity    int `json:"low_severity"`
}

// Stats contains scanning statistics
type Stats struct {
	FilesScanned int `json:"files_scanned"`
	FilesSkipped int `json:"files_skipped"`
}

// NewReporter creates a new reporter
func NewReporter(writer io.Writer, format string) *Reporter {
	return &Reporter{
		writer: writer,
		format: format,
	}
}

// GenerateReport generates a report from scan results
func (r *Reporter) GenerateReport(matches []*scanner.Match, filesScanned, filesSkipped int) error {
	switch r.format {
	case "json":
		return r.generateJSON(matches, filesScanned, filesSkipped)
	case "table":
		return r.generateTable(matches, filesScanned, filesSkipped)
	case "text", "":
		return r.generateText(matches, filesScanned, filesSkipped)
	default:
		return fmt.Errorf("unsupported report format: %s", r.format)
	}
}

// generateJSON generates a JSON formatted report
func (r *Reporter) generateJSON(matches []*scanner.Match, filesScanned, filesSkipped int) error {
	// Convert matches to report format
	reportMatches := make([]*MatchReport, len(matches))
	summary := &Summary{}

	for i, match := range matches {
		reportMatches[i] = &MatchReport{
			FilePath:    match.FilePath,
			LineNumber:  match.LineNumber,
			PatternName: match.Pattern.Name,
			Severity:    match.Pattern.Severity,
			Match:       match.MatchText,
			LineContent: match.LineContent,
		}

		summary.TotalMatches++
		switch match.Pattern.Severity {
		case "high":
			summary.HighSeverity++
		case "medium":
			summary.MediumSeverity++
		case "low":
			summary.LowSeverity++
		}
	}

	report := &JSONReport{
		Summary: summary,
		Matches: reportMatches,
		Stats: &Stats{
			FilesScanned: filesScanned,
			FilesSkipped: filesSkipped,
		},
	}

	encoder := json.NewEncoder(r.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// generateText generates a text formatted report
func (r *Reporter) generateText(matches []*scanner.Match, filesScanned, filesSkipped int) error {
	if len(matches) == 0 {
		fmt.Fprintf(r.writer, "✓ No secrets found!\n")
		fmt.Fprintf(r.writer, "Files scanned: %d\n", filesScanned)
		fmt.Fprintf(r.writer, "Files skipped: %d\n", filesSkipped)
		return nil
	}

	// Sort matches by file and line number
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].FilePath != matches[j].FilePath {
			return matches[i].FilePath < matches[j].FilePath
		}
		return matches[i].LineNumber < matches[j].LineNumber
	})

	// Count severities
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, match := range matches {
		switch match.Pattern.Severity {
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		}
	}

	// Header
	redBold := color.New(color.FgRed, color.Bold)
	yellowBold := color.New(color.FgYellow, color.Bold)
	greenBold := color.New(color.FgGreen, color.Bold)
	cyan := color.New(color.FgCyan)

	fmt.Fprintf(r.writer, "\n")
	redBold.Fprintf(r.writer, "⚠️  Secrets Found!\n")
	fmt.Fprintf(r.writer, "\n")

	if highCount > 0 {
		redBold.Fprintf(r.writer, "High Severity: %d\n", highCount)
	}
	if mediumCount > 0 {
		yellowBold.Fprintf(r.writer, "Medium Severity: %d\n", mediumCount)
	}
	if lowCount > 0 {
		greenBold.Fprintf(r.writer, "Low Severity: %d\n", lowCount)
	}

	fmt.Fprintf(r.writer, "\n")
	fmt.Fprintf(r.writer, "Files scanned: %d\n", filesScanned)
	fmt.Fprintf(r.writer, "Files skipped: %d\n", filesSkipped)
	fmt.Fprintf(r.writer, "\n")

	// Details
	fmt.Fprintf(r.writer, "─────────────────────────────────────────────────────\n")

	currentFile := ""
	for _, match := range matches {
		if match.FilePath != currentFile {
			currentFile = match.FilePath
			cyan.Fprintf(r.writer, "\n📄 %s\n", match.FilePath)
		}

		// Color based on severity
		var severityColor *color.Color
		var severityIcon string
		switch match.Pattern.Severity {
		case "high":
			severityColor = color.New(color.FgRed)
			severityIcon = "🔴"
		case "medium":
			severityColor = color.New(color.FgYellow)
			severityIcon = "🟡"
		case "low":
			severityColor = color.New(color.FgGreen)
			severityIcon = "🟢"
		}

		fmt.Fprintf(r.writer, "  Line %d: ", match.LineNumber)
		severityColor.Fprintf(r.writer, "%s %s", severityIcon, match.Pattern.Name)
		fmt.Fprintf(r.writer, "\n")
		fmt.Fprintf(r.writer, "    Content: %s\n", truncate(match.LineContent, 80))
		fmt.Fprintf(r.writer, "    Match: %s\n\n", truncate(match.MatchText, 60))
	}

	fmt.Fprintf(r.writer, "─────────────────────────────────────────────────────\n")
	return nil
}

// generateTable generates a table formatted report
func (r *Reporter) generateTable(matches []*scanner.Match, filesScanned, filesSkipped int) error {
	if len(matches) == 0 {
		fmt.Fprintf(r.writer, "No secrets found!\n")
		return nil
	}

	// Sort matches by file and line number
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].FilePath != matches[j].FilePath {
			return matches[i].FilePath < matches[j].FilePath
		}
		return matches[i].LineNumber < matches[j].LineNumber
	})

	// Print header
	fmt.Fprintf(r.writer, "%-50s | %-15s | %-10s | %-20s\n", "File", "Line", "Severity", "Pattern")
	fmt.Fprintf(r.writer, "%-50s-+-%-15s-+-%-10s-+-%-20s\n",
		"──────────────────────────────────────────────────",
		"───────────────",
		"──────────",
		"────────────────────")

	// Print rows
	for _, match := range matches {
		filePath := match.FilePath
		if len(filePath) > 50 {
			filePath = "..." + filePath[len(filePath)-47:]
		}
		fmt.Fprintf(r.writer, "%-50s | %15d | %-10s | %-20s\n",
			filePath,
			match.LineNumber,
			match.Pattern.Severity,
			truncate(match.Pattern.Name, 20))
	}

	fmt.Fprintf(r.writer, "\n")
	fmt.Fprintf(r.writer, "Total matches: %d\n", len(matches))
	fmt.Fprintf(r.writer, "Files scanned: %d\n", filesScanned)
	fmt.Fprintf(r.writer, "Files skipped: %d\n", filesSkipped)

	return nil
}

// truncate truncates a string to a maximum length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
