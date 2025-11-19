package main

import (
	"fmt"
	"os"

	"github.com/deadrootsec/goscout/pkg/llm"
	"github.com/spf13/cobra"
)

var (
	version = "0.2.0"
)

var (
	logAIPath    string
	secretsScan  bool
	versionFlag  bool
	showPatterns bool
)

var rootCmd = &cobra.Command{
	Use:   "goscout",
	Short: "GoScout - Your local scout agent",
	Long: `GoScout can analyze log files, search for secrets in repo, and many more.

Examples:
  goscout --logai /path/to/log.txt
  goscout --secrets /path/to/repo`,
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
			return analyzeLogWithAI(logAIPath, secretsScan)
		}

		// If no flags provided, show help
		return cmd.Help()
	},
}

func init() {
	rootCmd.Flags().StringVar(&logAIPath, "logai", "", "Path to log file to analyze with local LLM")
	rootCmd.Flags().BoolVar(&secretsScan, "secrets", false, "Scan for secrets in repo")
	rootCmd.Flags().BoolVarP(&versionFlag, "version", "v", false, "Show version")
	rootCmd.Flags().BoolVar(&showPatterns, "list-patterns", false, "List all available secret patterns")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func analyzeLogWithAI(logPath string, scanSecrets bool) error {
	fmt.Fprintf(os.Stderr, "🤖 Analyzing log file with local LLM...\n")
	fmt.Fprintf(os.Stderr, "📄 Log file: %s\n\n", logPath)

	// Create analyzer with default settings
	analyzer := llm.NewLogAnalyzer()

	// Verify Ollama is running
	fmt.Fprintf(os.Stderr, "⏳ Checking Ollama connection...\n")
	if err := analyzer.HealthCheck(); err != nil {
		return fmt.Errorf("❌ %w\nMake sure Ollama is running: ollama serve", err)
	}

	// Analyze the log file in chunks
	fmt.Fprintf(os.Stderr, "⏳ Querying %s model...\n\n", analyzer.Model)
	result, err := analyzer.AnalyzeLogFileChunked(logPath, scanSecrets)
	if err != nil {
		return fmt.Errorf("❌ Analysis failed: %w", err)
	}

	// Output results
	fmt.Fprintf(os.Stderr, "────────────────────────────────────────────────────────\n\n")
	fmt.Println(result)
	fmt.Fprintf(os.Stderr, "\n────────────────────────────────────────────────────────\n")
	fmt.Fprintf(os.Stderr, "✅ Analysis complete\n")

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
