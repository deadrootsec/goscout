package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/deadrootsec/goscout/pkg/scanner"
	"github.com/fatih/color"
)

// Report handles all report generation and output
type Report struct {
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

// AnalysisReport represents an AI analysis report
type AnalysisReport struct {
	Title     string
	Model     string
	Content   string
	Duration  string
	Timestamp string
}

// NewReport creates a new report
func NewReport(writer io.Writer, format string) *Report {
	return &Report{
		writer: writer,
		format: format,
	}
}

// GenerateSecrets generates a report from secret scan results
func (r *Report) GenerateSecrets(matches []*scanner.Match, filesScanned, filesSkipped int) error {
	switch r.format {
	case "json":
		return r.generateSecretsJSON(matches, filesScanned, filesSkipped)
	case "table":
		return r.generateSecretsTable(matches, filesScanned, filesSkipped)
	case "text", "":
		return r.generateSecretsText(matches, filesScanned, filesSkipped)
	default:
		return fmt.Errorf("unsupported report format: %s", r.format)
	}
}

// GenerateAnalysis generates a report from AI analysis
func (r *Report) GenerateAnalysis(analysis *AnalysisReport) error {
	fmt.Fprintf(r.writer, "────────────────────────────────────────────────────────\n\n")
	fmt.Fprintf(r.writer, "📊 %s\n", analysis.Title)
	fmt.Fprintf(r.writer, "🤖 Model: %s\n", analysis.Model)
	fmt.Fprintf(r.writer, "⏱️  Duration: %s\n\n", analysis.Duration)
	fmt.Fprintf(r.writer, "────────────────────────────────────────────────────────\n\n")
	fmt.Fprint(r.writer, analysis.Content)
	fmt.Fprintf(r.writer, "\n\n────────────────────────────────────────────────────────\n")
	return nil
}

// generateSecretsJSON generates a JSON formatted report
func (r *Report) generateSecretsJSON(matches []*scanner.Match, filesScanned, filesSkipped int) error {
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

// generateSecretsText generates a text formatted report
func (r *Report) generateSecretsText(matches []*scanner.Match, filesScanned, filesSkipped int) error {
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

// generateSecretsTable generates a table formatted report
func (r *Report) generateSecretsTable(matches []*scanner.Match, filesScanned, filesSkipped int) error {
	if len(matches) == 0 {
		fmt.Fprintf(r.writer, "No secrets found!\n")
		return nil
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].FilePath != matches[j].FilePath {
			return matches[i].FilePath < matches[j].FilePath
		}
		return matches[i].LineNumber < matches[j].LineNumber
	})

	fmt.Fprintf(r.writer, "%-50s | %-15s | %-10s | %-20s\n", "File", "Line", "Severity", "Pattern")
	fmt.Fprintf(r.writer, "%-50s-+-%-15s-+-%-10s-+-%-20s\n",
		"──────────────────────────────────────────────────",
		"───────────────",
		"──────────",
		"────────────────────")

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

// PrintPatterns prints available secret patterns
func PrintPatterns() {
	patterns := []struct {
		severity string
		items    []string
	}{
		{
			severity: "HIGH SEVERITY",
			items: []string{
				"AWS Access Key",
				"AWS Secret Access Key",
				"AWS Session Token",
				"Generic API Key",
				"Database Connection String",
				"GitHub Personal Access Token",
				"GitHub OAuth Token",
				"RSA Private Key",
				"OpenSSH Private Key",
				"PGP Private Key",
				"EC Private Key",
				"Google API Key",
				"Firebase Key",
				"Slack Token",
				"JWT Token",
				"Stripe API Key",
				"Twilio API Key",
				"Heroku API Key",
				"Basic Auth Credentials",
			},
		},
		{
			severity: "MEDIUM SEVERITY",
			items: []string{
				"Password in Code",
				"Secret Assignment",
				"Mailchimp API Key",
				"PagerDuty Token",
			},
		},
		{
			severity: "LOW SEVERITY",
			items: []string{
				"Private IP Address",
			},
		},
	}

	fmt.Println("Available Secret Patterns:")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("")

	for _, group := range patterns {
		fmt.Printf("%s:\n", group.severity)
		for _, item := range group.items {
			fmt.Printf("  - %s\n", item)
		}
		fmt.Println()
	}
}

// GetProgressMessage returns a formatted progress message
func GetProgressMessage(stage, detail string) string {
	icons := map[string]string{
		"scan":    "🔍",
		"analyze": "🤖",
		"process": "⚙️",
		"check":   "✓",
		"warning": "⚠️",
	}
	icon := icons[stage]
	if icon == "" {
		icon = "•"
	}
	return fmt.Sprintf("%s %s", icon, detail)
}
