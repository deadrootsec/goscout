package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/deadrootsec/goscout/pkg/llm"
	"github.com/deadrootsec/goscout/pkg/patterns"
)

// Match represents a found secret match
type Match struct {
	FilePath    string
	LineNumber  int
	MatchText   string
	Pattern     *patterns.Pattern
	LineContent string
}

// AnalyzedMatch contains a match along with AI analysis
type AnalyzedMatch struct {
	Match    *Match
	Analysis *llm.AnalysisResult
}

// ScanResult contains all matches found during a scan
type ScanResult struct {
	Matches      []*Match
	FilesScanned int
	FilesSkipped int
	Errors       []error
}

// ScanAndAnalyzeResult contains matches with AI analysis
type ScanAndAnalyzeResult struct {
	AnalyzedMatches []*AnalyzedMatch
	FilesScanned    int
	FilesSkipped    int
	Errors          []error
	AnalysisErrors  []error
}

// Scanner performs the actual scanning
type Scanner struct {
	excludeDirs  map[string]bool
	excludeFiles map[string]bool
	maxFileSize  int64
	analyzer     *llm.Analyzer
}

// NewScanner creates a new scanner instance
func NewScanner() *Scanner {
	return &Scanner{
		excludeDirs: map[string]bool{
			".git":         true,
			".hg":          true,
			".svn":         true,
			".bzr":         true,
			"node_modules": true,
			"vendor":       true,
			".venv":        true,
			"venv":         true,
			"env":          true,
			".env":         true,
			"dist":         true,
			"build":        true,
			"target":       true,
			".idea":        true,
			".vscode":      true,
			".DS_Store":    true,
		},
		excludeFiles: map[string]bool{
			".gitignore":        true,
			".dockerignore":     true,
			"package-lock.json": true,
			"yarn.lock":         true,
			"go.sum":            true,
		},
		maxFileSize: 10 * 1024 * 1024, // 10MB
		analyzer:    nil,
	}
}

// SetAnalyzer sets the LLM analyzer for AI-powered analysis
func (s *Scanner) SetAnalyzer(analyzer *llm.Analyzer) {
	s.analyzer = analyzer
}

// AddExcludeDir adds a directory to the exclusion list
func (s *Scanner) AddExcludeDir(dir string) {
	s.excludeDirs[dir] = true
}

// AddExcludeFile adds a file to the exclusion list
func (s *Scanner) AddExcludeFile(file string) {
	s.excludeFiles[file] = true
}

// SetMaxFileSize sets the maximum file size to scan
func (s *Scanner) SetMaxFileSize(size int64) {
	s.maxFileSize = size
}

// ScanPath scans a directory for secrets
func (s *Scanner) ScanPath(path string) (*ScanResult, error) {
	result := &ScanResult{
		Matches: make([]*Match, 0),
		Errors:  make([]error, 0),
	}

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("error accessing %s: %w", filePath, err))
			return nil
		}

		// Skip directories
		if info.IsDir() {
			if s.shouldSkipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip excluded files
		if s.excludeFiles[info.Name()] {
			result.FilesSkipped++
			return nil
		}

		// Skip binary files
		if s.isBinaryFile(filePath) {
			result.FilesSkipped++
			return nil
		}

		// Skip large files
		if info.Size() > s.maxFileSize {
			result.FilesSkipped++
			return nil
		}

		// Scan the file
		matches, err := s.scanFile(filePath)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("error scanning %s: %w", filePath, err))
			result.FilesSkipped++
			return nil
		}

		result.Matches = append(result.Matches, matches...)
		result.FilesScanned++

		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

// ScanPathWithAnalysis scans a directory for secrets and analyzes them with AI
func (s *Scanner) ScanPathWithAnalysis(path string) (*ScanAndAnalyzeResult, error) {
	if s.analyzer == nil {
		return nil, fmt.Errorf("analyzer not set: call SetAnalyzer() first")
	}

	// First, perform the initial scan
	scanResult, err := s.ScanPath(path)
	if err != nil {
		return nil, err
	}

	// Prepare result
	result := &ScanAndAnalyzeResult{
		AnalyzedMatches: make([]*AnalyzedMatch, 0),
		FilesScanned:    scanResult.FilesScanned,
		FilesSkipped:    scanResult.FilesSkipped,
		Errors:          scanResult.Errors,
		AnalysisErrors:  make([]error, 0),
	}

	// Analyze each match with the LLM
	for _, match := range scanResult.Matches {
		analyzedMatch, err := s.analyzeMatch(match)
		if err != nil {
			result.AnalysisErrors = append(result.AnalysisErrors, fmt.Errorf("failed to analyze match in %s:%d: %w", match.FilePath, match.LineNumber, err))
			continue
		}
		result.AnalyzedMatches = append(result.AnalyzedMatches, analyzedMatch)
	}

	return result, nil
}

// analyzeMatch sends a secret match to the analyzer for detailed analysis
func (s *Scanner) analyzeMatch(match *Match) (*AnalyzedMatch, error) {
	// Create a prompt that includes the matched secret and context
	prompt := llm.SecretsAnalysisPrompt(match.LineContent)

	// Query the analyzer
	analysis, err := s.analyzer.Query(prompt)
	if err != nil {
		return nil, err
	}

	return &AnalyzedMatch{
		Match:    match,
		Analysis: analysis,
	}, nil
}

// scanFile scans a single file for secrets
func (s *Scanner) scanFile(filePath string) ([]*Match, error) {
	var matches []*Match

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Check against all patterns
		for _, pattern := range patterns.GetPatterns() {
			if pattern.Regex.MatchString(line) {
				match := &Match{
					FilePath:    filePath,
					LineNumber:  lineNumber,
					MatchText:   pattern.Regex.FindString(line),
					Pattern:     &pattern,
					LineContent: line,
				}
				matches = append(matches, match)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return matches, nil
}

// shouldSkipDir checks if a directory should be skipped
func (s *Scanner) shouldSkipDir(dirName string) bool {
	return s.excludeDirs[dirName]
}

// isBinaryFile checks if a file is likely binary
func (s *Scanner) isBinaryFile(filePath string) bool {
	binaryExtensions := map[string]bool{
		".exe":    true,
		".dll":    true,
		".so":     true,
		".dylib":  true,
		".bin":    true,
		".o":      true,
		".a":      true,
		".pyc":    true,
		".pyo":    true,
		".class":  true,
		".jar":    true,
		".zip":    true,
		".tar":    true,
		".gz":     true,
		".7z":     true,
		".rar":    true,
		".png":    true,
		".jpg":    true,
		".jpeg":   true,
		".gif":    true,
		".pdf":    true,
		".db":     true,
		".sqlite": true,
		".iso":    true,
	}

	ext := filepath.Ext(filePath)
	return binaryExtensions[strings.ToLower(ext)]
}
