package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/deadrootsec/goscout/pkg/llm"
	"github.com/deadrootsec/goscout/pkg/report"
	"github.com/deadrootsec/goscout/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	version = "0.2.0"
)

var (
	format       string
	maxFileSize  int64
	excludeDirs  []string
	excludeFiles []string
	severity     string
	versionFlag  bool
	jsonOutput   bool
	showPatterns bool
	logAIPath    string
	logAIPrompt  string
)

var rootCmd = &cobra.Command{
	Use:   "goscout [path]",
	Short: "GoScout - Local Secret Scanner",
	Long: `GoScout is a simple and fast secret scanner for scanning repositories.
It scans your codebase locally without sending data to any external service.

Example:
  goscout .
  goscout /path/to/repo
  goscout . --format json
  goscout . --severity high`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Handle version flag
		if versionFlag {
			fmt.Printf("GoScout version %s\n", version)
			return nil
		}

		// Handle list patterns
		if showPatterns {
			return listPatterns()
		}

		// Handle log AI analysis
		if logAIPath != "" {
			if logAIPrompt == "" {
				return fmt.Errorf("--prompt is required when using --logai")
			}
			return analyzeLogWithAI(logAIPath, logAIPrompt)
		}

		// Default to scanning current directory
		scanPath := "."
		if len(args) > 0 {
			scanPath = args[0]
		}

		return performScan(scanPath)
	},
}

func init() {
	rootCmd.Flags().StringVarP(&format, "format", "f", "text", "Output format (text, json, table)")
	rootCmd.Flags().Int64VarP(&maxFileSize, "max-size", "s", 10*1024*1024, "Max file size to scan in bytes (default 10MB)")
	rootCmd.Flags().StringSliceVar(&excludeDirs, "exclude-dirs", nil, "Additional directories to exclude")
	rootCmd.Flags().StringSliceVar(&excludeFiles, "exclude-files", nil, "Additional files to exclude")
	rootCmd.Flags().StringVarP(&severity, "severity", "S", "", "Filter results by severity (high, medium, low)")
	rootCmd.Flags().BoolVarP(&versionFlag, "version", "v", false, "Show version")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output JSON format (shorthand for --format json)")
	rootCmd.Flags().BoolVar(&showPatterns, "list-patterns", false, "List all available patterns")
	rootCmd.Flags().StringVar(&logAIPath, "logai", "", "Path to log file to analyze with local LLM (requires --prompt)")
	rootCmd.Flags().StringVar(&logAIPrompt, "prompt", "", "Prompt for LLM analysis of log file (use with --logai)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func performScan(scanPath string) error {
	// Handle json shorthand
	if jsonOutput {
		format = "json"
	}

	// Validate path exists
	if _, err := os.Stat(scanPath); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", scanPath)
	}

	// Get absolute path
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	fmt.Fprintf(os.Stderr, "🔍 Scanning: %s\n", absPath)
	fmt.Fprintf(os.Stderr, "📋 Format: %s\n\n", format)

	// Create and configure scanner
	sc := scanner.NewScanner()
	sc.SetMaxFileSize(maxFileSize)

	// Add excluded directories
	for _, dir := range excludeDirs {
		sc.AddExcludeDir(dir)
	}

	// Add excluded files
	for _, file := range excludeFiles {
		sc.AddExcludeFile(file)
	}

	// Perform scan
	results, err := sc.ScanPath(absPath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Filter by severity if specified
	if severity != "" {
		filtered := make([]*scanner.Match, 0)
		for _, match := range results.Matches {
			if match.Pattern.Severity == severity {
				filtered = append(filtered, match)
			}
		}
		results.Matches = filtered
	}

	// Generate report
	reporter := report.NewReporter(os.Stdout, format)
	if err := reporter.GenerateReport(results.Matches, results.FilesScanned, results.FilesSkipped); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Exit with error code if issues found
	if len(results.Matches) > 0 {
		os.Exit(1)
	}

	return nil
}

func analyzeLogWithAI(logPath, prompt string) error {
	fmt.Fprintf(os.Stderr, "🤖 Analyzing log file with local LLM...\n")
	fmt.Fprintf(os.Stderr, "📄 Log file: %s\n", logPath)
	fmt.Fprintf(os.Stderr, "💬 Prompt: %s\n\n", prompt)

	// Create analyzer with default settings (qwen:1.8b)
	analyzer := llm.NewLogAnalyzer()

	// Verify Ollama is running
	fmt.Fprintf(os.Stderr, "⏳ Checking Ollama connection...\n")
	if err := analyzer.HealthCheck(); err != nil {
		return fmt.Errorf("❌ %w\nMake sure Ollama is running: ollama serve", err)
	}

	// Analyze the log file
	fmt.Fprintf(os.Stderr, "⏳ Querying %s model...\n\n", analyzer.Model)
	result, err := analyzer.AnalyzeLogFile(logPath, prompt)
	if err != nil {
		return fmt.Errorf("❌ Analysis failed: %w", err)
	}

	// Output results
	fmt.Fprintf(os.Stderr, "✅ Analysis complete\n")
	fmt.Fprintf(os.Stderr, "⏱️  Duration: %.2f seconds\n\n", result.Duration.Seconds())
	fmt.Fprintf(os.Stderr, "────────────────────────────────────────────────────────\n\n")
	fmt.Println(result.Findings)
	fmt.Fprintf(os.Stderr, "\n────────────────────────────────────────────────────────\n")

	return nil
}

func listPatterns() error {
	fmt.Println("Available Secret Patterns:")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("")
	fmt.Println("HIGH SEVERITY:")
	fmt.Println("  - AWS Access Key ID")
	fmt.Println("  - AWS Secret Access Key")
	fmt.Println("  - AWS Session Token")
	fmt.Println("  - Generic API Key")
	fmt.Println("  - Database Connection String")
	fmt.Println("  - PostgreSQL Password")
	fmt.Println("  - MySQL Password")
	fmt.Println("  - GitHub Personal Access Token")
	fmt.Println("  - GitHub OAuth Token")
	fmt.Println("  - RSA Private Key")
	fmt.Println("  - OpenSSH Private Key")
	fmt.Println("  - PGP Private Key")
	fmt.Println("  - EC Private Key")
	fmt.Println("  - Google API Key")
	fmt.Println("  - Firebase Key")
	fmt.Println("  - Slack Token")
	fmt.Println("  - JWT Token")
	fmt.Println("  - Stripe API Key")
	fmt.Println("  - Twilio API Key")
	fmt.Println("")
	fmt.Println("MEDIUM SEVERITY:")
	fmt.Println("  - Password in Code")
	fmt.Println("  - Secret Assignment")
	fmt.Println("  - Mailchimp API Key")
	fmt.Println("")
	fmt.Println("LOW SEVERITY:")
	fmt.Println("  - Private IP Address")
	fmt.Println("")

	return nil
}
