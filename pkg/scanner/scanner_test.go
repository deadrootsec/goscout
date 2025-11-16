package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewScanner(t *testing.T) {
	scanner := NewScanner()
	if scanner == nil {
		t.Fatal("NewScanner() returned nil")
	}
	if scanner.maxFileSize != 10*1024*1024 {
		t.Errorf("expected max file size 10MB, got %d", scanner.maxFileSize)
	}
}

func TestScannerAddExcludeDir(t *testing.T) {
	scanner := NewScanner()
	scanner.AddExcludeDir("test_dir")

	if !scanner.excludeDirs["test_dir"] {
		t.Error("AddExcludeDir failed to add directory")
	}
}

func TestScannerAddExcludeFile(t *testing.T) {
	scanner := NewScanner()
	scanner.AddExcludeFile("test.txt")

	if !scanner.excludeFiles["test.txt"] {
		t.Error("AddExcludeFile failed to add file")
	}
}

func TestScannerSetMaxFileSize(t *testing.T) {
	scanner := NewScanner()
	newSize := int64(5 * 1024 * 1024)
	scanner.SetMaxFileSize(newSize)

	if scanner.maxFileSize != newSize {
		t.Errorf("expected max file size %d, got %d", newSize, scanner.maxFileSize)
	}
}

func TestScannerShouldSkipDir(t *testing.T) {
	scanner := NewScanner()

	tests := []struct {
		dirName string
		want    bool
	}{
		{".git", true},
		{"node_modules", true},
		{"src", false},
		{"vendor", true},
	}

	for _, tt := range tests {
		if got := scanner.shouldSkipDir(tt.dirName); got != tt.want {
			t.Errorf("shouldSkipDir(%q) = %v, want %v", tt.dirName, got, tt.want)
		}
	}
}

func TestScannerIsBinaryFile(t *testing.T) {
	scanner := NewScanner()

	tests := []struct {
		filePath string
		want     bool
	}{
		{"test.exe", true},
		{"test.dll", true},
		{"test.so", true},
		{"test.go", false},
		{"test.txt", false},
		{"README.md", false},
		{"binary.bin", true},
		{"archive.zip", true},
		{"image.png", true},
		{"image.jpg", true},
		{"document.pdf", true},
	}

	for _, tt := range tests {
		if got := scanner.isBinaryFile(tt.filePath); got != tt.want {
			t.Errorf("isBinaryFile(%q) = %v, want %v", tt.filePath, got, tt.want)
		}
	}
}

func TestScannerScanFile(t *testing.T) {
	// Create a temporary test file with a secret
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	content := `
password = "my_secret_password"
api_key = "sk_test_1234567890"
normal content
`

	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	scanner := NewScanner()
	matches, err := scanner.scanFile(testFile)

	if err != nil {
		t.Fatalf("scanFile() returned error: %v", err)
	}

	if len(matches) == 0 {
		t.Error("expected matches, got none")
	}
}

func TestScannerScanPath(t *testing.T) {
	// Create a temporary directory with test files
	tmpDir := t.TempDir()

	// Create a test file with secrets
	testFile := filepath.Join(tmpDir, "config.txt")
	content := `
# Database config
password = "super_secret"
api_key = "test_key_12345678"
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Create a subdirectory to exclude
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.Mkdir(gitDir, 0755); err != nil {
		t.Fatalf("failed to create .git directory: %v", err)
	}

	gitFile := filepath.Join(gitDir, "config")
	if err := os.WriteFile(gitFile, []byte("password=hidden"), 0644); err != nil {
		t.Fatalf("failed to create .git file: %v", err)
	}

	scanner := NewScanner()
	result, err := scanner.ScanPath(tmpDir)

	if err != nil {
		t.Fatalf("ScanPath() returned error: %v", err)
	}

	if result == nil {
		t.Fatal("ScanPath() returned nil result")
	}

	if result.FilesScanned == 0 {
		t.Error("expected files to be scanned")
	}

	// Files in .git should be skipped
	if result.FilesSkipped == 0 {
		t.Error("expected some files to be skipped")
	}
}

func TestScannerScanPathNonExistent(t *testing.T) {
	scanner := NewScanner()
	_, err := scanner.ScanPath("/path/that/does/not/exist")

	// Should return an error when path doesn't exist
	if err == nil {
		t.Error("expected error for non-existent path")
	}
}

func TestScannerExcludesLargeFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a large file
	largeFile := filepath.Join(tmpDir, "large.txt")
	largContent := make([]byte, 11*1024*1024) // 11MB
	if err := os.WriteFile(largeFile, largContent, 0644); err != nil {
		t.Fatalf("failed to create large file: %v", err)
	}

	scanner := NewScanner()
	result, err := scanner.ScanPath(tmpDir)

	if err != nil {
		t.Fatalf("ScanPath() returned error: %v", err)
	}

	if result.FilesSkipped == 0 {
		t.Error("expected large file to be skipped")
	}
}

func TestScannerMultipleMatches(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file with multiple secrets
	testFile := filepath.Join(tmpDir, "secrets.txt")
	content := `
password = "secret1"
api_key = "key123456789"
password = "secret2"
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
`

	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	scanner := NewScanner()
	result, err := scanner.ScanPath(tmpDir)

	if err != nil {
		t.Fatalf("ScanPath() returned error: %v", err)
	}

	if len(result.Matches) < 2 {
		t.Errorf("expected at least 2 matches, got %d", len(result.Matches))
	}
}

func TestScannerEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an empty file
	testFile := filepath.Join(tmpDir, "empty.txt")
	if err := os.WriteFile(testFile, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	scanner := NewScanner()
	result, err := scanner.ScanPath(tmpDir)

	if err != nil {
		t.Fatalf("ScanPath() returned error: %v", err)
	}

	// Should scan the file but find no matches
	if result.FilesScanned == 0 {
		t.Error("expected file to be scanned")
	}
}

func TestScanResultStructure(t *testing.T) {
	result := &ScanResult{
		Matches:      make([]*Match, 0),
		FilesScanned: 5,
		FilesSkipped: 2,
		Errors:       make([]error, 0),
	}

	if result.FilesScanned != 5 {
		t.Errorf("expected 5 files scanned, got %d", result.FilesScanned)
	}

	if result.FilesSkipped != 2 {
		t.Errorf("expected 2 files skipped, got %d", result.FilesSkipped)
	}

	if len(result.Matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(result.Matches))
	}
}

func TestMatchStructure(t *testing.T) {
	match := &Match{
		FilePath:    "/path/to/file.txt",
		LineNumber:  42,
		MatchText:   "api_key = secret",
		LineContent: "api_key = secret_value",
	}

	if match.FilePath != "/path/to/file.txt" {
		t.Error("FilePath not set correctly")
	}

	if match.LineNumber != 42 {
		t.Error("LineNumber not set correctly")
	}

	if match.MatchText != "api_key = secret" {
		t.Error("MatchText not set correctly")
	}
}
