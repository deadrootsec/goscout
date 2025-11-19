package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/deadrootsec/goscout/pkg/llm"
	"github.com/deadrootsec/goscout/pkg/report"
	"github.com/deadrootsec/goscout/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	version = "0.3.0"
)

var (
	// Flags
	versionFlag  bool
	showPatterns bool
	secretsScan  bool
	logAIPath    string
	format       string
	maxFileSize  int64
	excludeDirs  []string
	excludeFiles []string
	severity     string
	jsonOutput   bool
	defaultModel string
	chunkLines   int
	ollamaURL    string
)

var rootCmd = &cobra.Command{
	Use:   "goscout",
	Short: "GoScout - tool for scouting your machine, logs, repos and many more",
	Long: `GoScout scans repositories for secrets, machines for interesting information and logs and analysis it using local LLM.
All processing happens locally without sending data to external services.

Examples:
  goscout --secrets
  goscout --secrets /path/to/repo
  goscout --logai /path/to/log.txt
  goscout --list-patterns
  goscout --version`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if versionFlag {
			fmt.Printf("GoScout version %s\n", version)
			return nil
		}

		if showPatterns {
			report.PrintPatterns()
			return nil
		}

		if logAIPath != "" {
			return analyzeLogWithAI(logAIPath)
		}

		if secretsScan {
			scanPath := "."
			if len(args) > 0 {
				scanPath = args[0]
			}
			return performSecretsScan(scanPath)
		}

		return cmd.Help()
	},
}

func init() {
	rootCmd.Flags().BoolVarP(&versionFlag, "version", "v", false, "Show version")
	rootCmd.Flags().BoolVar(&showPatterns, "list-patterns", false, "List all available secret patterns")
	rootCmd.Flags().BoolVar(&secretsScan, "secrets", false, "Scan repository for secrets")
	rootCmd.Flags().StringVar(&logAIPath, "logai", "", "Path to log file to analyze with local LLM")
	rootCmd.Flags().StringVarP(&format, "format", "f", "text", "Output format (text, json, table)")
	rootCmd.Flags().Int64VarP(&maxFileSize, "max-size", "s", 10*1024*1024, "Max file size to scan in bytes (default 10MB)")
	rootCmd.Flags().StringSliceVar(&excludeDirs, "exclude-dirs", nil, "Additional directories to exclude")
	rootCmd.Flags().StringSliceVar(&excludeFiles, "exclude-files", nil, "Additional files to exclude")
	rootCmd.Flags().StringVarP(&severity, "severity", "S", "", "Filter results by severity (high, medium, low)")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output JSON format (shorthand for --format json)")
	rootCmd.Flags().StringVar(&defaultModel, "model", llm.DefaultModel, "LLM model to use for analysis")
	rootCmd.Flags().IntVar(&chunkLines, "chunk-lines", llm.DefaultChunkLines, "Lines per chunk for analysis (default 2000)")
	rootCmd.Flags().StringVar(&ollamaURL, "ollama-url", llm.OllamaDefaultURL, "Ollama server URL")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func performSecretsScan(scanPath string) error {
	if jsonOutput {
		format = "json"
	}

	if _, err := os.Stat(scanPath); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", scanPath)
	}

	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	fmt.Fprintf(os.Stderr, "🔍 Scanning: %s\n", absPath)
	fmt.Fprintf(os.Stderr, "📋 Format: %s\n\n", format)

	sc := scanner.NewScanner()
	sc.SetMaxFileSize(maxFileSize)

	for _, dir := range excludeDirs {
		sc.AddExcludeDir(dir)
	}

	for _, file := range excludeFiles {
		sc.AddExcludeFile(file)
	}

	results, err := sc.ScanPath(absPath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if severity != "" {
		filtered := make([]*scanner.Match, 0)
		for _, match := range results.Matches {
			if match.Pattern.Severity == severity {
				filtered = append(filtered, match)
			}
		}
		results.Matches = filtered
	}

	rpt := report.NewReport(os.Stdout, format)
	if err := rpt.GenerateSecrets(results.Matches, results.FilesScanned, results.FilesSkipped); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	if len(results.Matches) > 0 {
		os.Exit(1)
	}

	return nil
}

func analyzeLogWithAI(logPath string) error {
	fmt.Fprintf(os.Stderr, "🤖 Analyzing log file with local LLM...\n")
	fmt.Fprintf(os.Stderr, "📄 Log file: %s\n\n", logPath)

	analyzer := llm.NewAnalyzer()
	analyzer.SetModel(defaultModel)
	analyzer.SetOllamaURL(ollamaURL)
	analyzer.SetChunkLines(chunkLines)

	fmt.Fprintf(os.Stderr, "⏳ Checking Ollama connection...\n")
	if err := analyzer.HealthCheck(); err != nil {
		return fmt.Errorf("❌ %w\nMake sure Ollama is running: ollama serve", err)
	}

	file, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	// Split file into chunks
	chunks := make([]string, 0)
	var currentChunk strings.Builder
	var lineCount int

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		currentChunk.WriteString(line)
		currentChunk.WriteString("\n")
		lineCount++

		if lineCount >= chunkLines {
			chunks = append(chunks, currentChunk.String())
			currentChunk.Reset()
			lineCount = 0
		}
	}

	if currentChunk.Len() > 0 {
		chunks = append(chunks, currentChunk.String())
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading log file: %w", err)
	}

	if len(chunks) == 0 {
		return fmt.Errorf("log file is empty")
	}

	fmt.Fprintf(os.Stderr, "⏳ Querying %s model...\n\n", analyzer.Model)

	var results strings.Builder
	for i, chunk := range chunks {
		fmt.Fprintf(os.Stderr, "📊 Processing chunk %d/%d...\n", i+1, len(chunks))

		prompt := llm.LogAnalysisPrompt(chunk)
		result, err := analyzer.Query(prompt)
		if err != nil {
			return fmt.Errorf("❌ Analysis failed: %w", err)
		}

		results.WriteString(fmt.Sprintf("=== Chunk %d Summary ===\n", i+1))
		results.WriteString(result.Findings)
		results.WriteString("\n\n")
	}

	analysisReport := &report.AnalysisReport{
		Title:    "Log Analysis Results",
		Model:    analyzer.Model,
		Content:  results.String(),
		Duration: "see above",
	}

	rpt := report.NewReport(os.Stdout, "text")
	if err := rpt.GenerateAnalysis(analysisReport); err != nil {
		return fmt.Errorf("failed to generate analysis report: %w", err)
	}

	fmt.Fprintf(os.Stderr, "✅ Analysis complete\n")

	return nil
}
