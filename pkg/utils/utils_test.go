package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileExists(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "test_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Test existing file
	if !FileExists(tmpFile.Name()) {
		t.Error("FileExists returned false for existing file")
	}

	// Test non-existing file
	if FileExists("/non/existent/path/file.txt") {
		t.Error("FileExists returned true for non-existing file")
	}
}

func TestIsDirectory(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "test_dir_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Test directory
	if !IsDirectory(tmpDir) {
		t.Error("IsDirectory returned false for directory")
	}

	// Create a file in the directory
	tmpFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test file
	if IsDirectory(tmpFile) {
		t.Error("IsDirectory returned true for file")
	}

	// Test non-existent path
	if IsDirectory("/non/existent/path") {
		t.Error("IsDirectory returned true for non-existent path")
	}
}

func TestGetAbsPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_abs_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	absPath, err := GetAbsPath(tmpDir)
	if err != nil {
		t.Fatalf("GetAbsPath failed: %v", err)
	}

	if !filepath.IsAbs(absPath) {
		t.Error("GetAbsPath did not return absolute path")
	}

	if absPath != tmpDir {
		t.Errorf("GetAbsPath returned %s, expected %s", absPath, tmpDir)
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello world", 8, "hello..."},
		{"12345678", 5, "12..."},
		{"a", 0, "..."},
		{"", 5, ""},
		{"very long string that needs truncation", 20, "very long string..."},
	}

	for _, tt := range tests {
		result := TruncateString(tt.input, tt.maxLen)
		if result != tt.expected {
			t.Errorf("TruncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expected)
		}
	}
}

func TestContainsString(t *testing.T) {
	slice := []string{"apple", "banana", "cherry"}

	tests := []struct {
		item     string
		expected bool
	}{
		{"apple", true},
		{"banana", true},
		{"cherry", true},
		{"date", false},
		{"", false},
	}

	for _, tt := range tests {
		result := ContainsString(slice, tt.item)
		if result != tt.expected {
			t.Errorf("ContainsString(%v, %q) = %v, want %v", slice, tt.item, result, tt.expected)
		}
	}
}

func TestRemoveDuplicates(t *testing.T) {
	tests := []struct {
		input    []string
		expected []string
	}{
		{
			[]string{"a", "b", "c"},
			[]string{"a", "b", "c"},
		},
		{
			[]string{"a", "a", "b"},
			[]string{"a", "b"},
		},
		{
			[]string{"a", "b", "a", "c", "b"},
			[]string{"a", "b", "c"},
		},
		{
			[]string{},
			[]string{},
		},
		{
			[]string{"a", "a", "a"},
			[]string{"a"},
		},
	}

	for _, tt := range tests {
		result := RemoveDuplicates(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("RemoveDuplicates(%v) length = %d, want %d", tt.input, len(result), len(tt.expected))
			continue
		}

		for i, v := range result {
			if v != tt.expected[i] {
				t.Errorf("RemoveDuplicates(%v)[%d] = %q, want %q", tt.input, i, v, tt.expected[i])
			}
		}
	}
}

func TestParseBytes(t *testing.T) {
	tests := []struct {
		input     string
		expected  int64
		shouldErr bool
	}{
		{"1024", 1024, false},
		{"1B", 1, false},
		{"1KB", 1024, false},
		{"1MB", 1024 * 1024, false},
		{"1GB", 1024 * 1024 * 1024, false},
		{"10MB", 10 * 1024 * 1024, false},
		{"5.5MB", 0, true},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		result, err := ParseBytes(tt.input)
		if (err != nil) != tt.shouldErr {
			t.Errorf("ParseBytes(%q) error = %v, shouldErr = %v", tt.input, err, tt.shouldErr)
		}

		if !tt.shouldErr && result != tt.expected {
			t.Errorf("ParseBytes(%q) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input  int64
		minLen int
	}{
		{1024, 1},
		{1024 * 1024, 1},
		{1024 * 1024 * 1024, 1},
		{0, 1},
	}

	for _, tt := range tests {
		result := FormatBytes(tt.input)
		if len(result) < tt.minLen {
			t.Errorf("FormatBytes(%d) = %q, expected length >= %d", tt.input, result, tt.minLen)
		}
	}
}

func TestNormalizePathSeparators(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"path/to/file", "path/to/file"},
		{"path\\to\\file", "path/to/file"},
		{"C:\\Users\\test", "C:/Users/test"},
		{"/home/user/file", "/home/user/file"},
	}

	for _, tt := range tests {
		result := NormalizePathSeparators(tt.input)
		if result != tt.expected {
			t.Errorf("NormalizePathSeparators(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestIsTextFile(t *testing.T) {
	tests := []struct {
		filename string
		expected bool
	}{
		{"test.go", true},
		{"test.py", true},
		{"test.json", true},
		{"test.yaml", true},
		{"test.env", true},
		{"test.exe", false},
		{"test.bin", false},
		{"test.png", false},
		{"test.zip", false},
		{"README.md", true},
		{".gitignore", true},
		{"Dockerfile", false},
	}

	for _, tt := range tests {
		result := IsTextFile(tt.filename)
		if result != tt.expected {
			t.Errorf("IsTextFile(%q) = %v, want %v", tt.filename, result, tt.expected)
		}
	}
}

func TestGetRelativePath(t *testing.T) {
	tests := []struct {
		targetPath string
		basePath   string
		minLen     int
	}{
		{"/home/user/file.txt", "/home/user", 1},
		{"/home/user/dir/file.txt", "/home/user", 1},
		{"/home/user", "/home/user", 1},
	}

	for _, tt := range tests {
		result := GetRelativePath(tt.targetPath, tt.basePath)
		if len(result) < tt.minLen {
			t.Errorf("GetRelativePath(%q, %q) = %q, expected length >= %d", tt.targetPath, tt.basePath, result, tt.minLen)
		}
	}
}

func TestCleanPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/path/to/./file", "/path/to/file"},
		{"/path/to/../file", "/path/file"},
		{"/path//to/file", "/path/to/file"},
		{"./path/to/file", "path/to/file"},
	}

	for _, tt := range tests {
		result := CleanPath(tt.input)
		if result != tt.expected {
			t.Errorf("CleanPath(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestHighlightMatch(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
	}{
		{"short", 40},
		{"this is a very long string that should be truncated", 40},
	}

	for _, tt := range tests {
		result := HighlightMatch(tt.input, tt.input)
		if len(result) > 43 { // 40 + "..."
			t.Errorf("HighlightMatch result too long: %q (len=%d)", result, len(result))
		}
	}
}
