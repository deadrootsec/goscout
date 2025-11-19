package llm

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewLogAnalyzer(t *testing.T) {
	analyzer := NewLogAnalyzer()

	if analyzer.OllamaURL != OllamaDefaultURL {
		t.Errorf("expected OllamaURL %s, got %s", OllamaDefaultURL, analyzer.OllamaURL)
	}

	if analyzer.Model != DefaultModel {
		t.Errorf("expected Model %s, got %s", DefaultModel, analyzer.Model)
	}

	if analyzer.Client == nil {
		t.Error("expected Client to be initialized, got nil")
	}
}

func TestSetModel(t *testing.T) {
	analyzer := NewLogAnalyzer()
	newModel := "phi:2.7b"
	analyzer.SetModel(newModel)

	if analyzer.Model != newModel {
		t.Errorf("expected Model %s, got %s", newModel, analyzer.Model)
	}
}

func TestSetOllamaURL(t *testing.T) {
	analyzer := NewLogAnalyzer()
	newURL := "http://192.168.1.100:11434"
	analyzer.SetOllamaURL(newURL)

	if analyzer.OllamaURL != newURL {
		t.Errorf("expected OllamaURL %s, got %s", newURL, analyzer.OllamaURL)
	}
}

func TestReadLogFile(t *testing.T) {
	// Create a temporary log file
	tmpFile, err := os.CreateTemp("", "test_log_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write test content
	testContent := "test log line 1\ntest log line 2\ntest log line 3"
	if _, err := tmpFile.WriteString(testContent); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Test reading small file
	content, err := readLogFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("readLogFile failed: %v", err)
	}

	if content != testContent {
		t.Errorf("expected content %q, got %q", testContent, content)
	}
}

func TestReadLogFileNotFound(t *testing.T) {
	_, err := readLogFile("/non/existent/file.log")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

func TestReadLogFileLarge(t *testing.T) {
	// Create a temporary file with content larger than MaxLogSize
	tmpFile, err := os.CreateTemp("", "test_large_log_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write content larger than MaxLogSize
	largeContent := ""
	for i := 0; i < 100; i++ {
		largeContent += "x"
	}
	largeContent = largeContent + "\n"
	for i := 0; i < 1000; i++ {
		tmpFile.WriteString(largeContent)
	}
	tmpFile.Close()

	content, err := readLogFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("readLogFile failed: %v", err)
	}

	// Verify that content was limited
	if len(content) > MaxLogSize {
		t.Errorf("expected content size <= %d, got %d", MaxLogSize, len(content))
	}
}

func TestBuildAnalysisPrompt(t *testing.T) {
	userPrompt := "Find errors"
	logContent := "error log content here"

	prompt := buildAnalysisPrompt(userPrompt, logContent)

	if !contains(prompt, userPrompt) {
		t.Errorf("prompt should contain user prompt %q", userPrompt)
	}

	if !contains(prompt, logContent) {
		t.Errorf("prompt should contain log content")
	}

	if !contains(prompt, "log security analyst") {
		t.Errorf("prompt should contain security analyst role")
	}
}

func TestBuildAnalysisPromptEmpty(t *testing.T) {
	prompt := buildAnalysisPrompt("", "")

	if prompt == "" {
		t.Error("expected prompt to not be empty")
	}
}

func TestAnalysisResultFields(t *testing.T) {
	result := &AnalysisResult{
		Findings: "test findings",
		Model:    "qwen:1.8b",
		Duration: 5 * time.Second,
	}

	if result.Findings != "test findings" {
		t.Errorf("expected Findings %q, got %q", "test findings", result.Findings)
	}

	if result.Model != "qwen:1.8b" {
		t.Errorf("expected Model %q, got %q", "qwen:1.8b", result.Model)
	}

	if result.Duration != 5*time.Second {
		t.Errorf("expected Duration 5s, got %v", result.Duration)
	}
}

func TestOllamaRequestJSON(t *testing.T) {
	req := OllamaRequest{
		Model:  "qwen:1.8b",
		Prompt: "test prompt",
		Stream: false,
	}

	// Verify struct can be marshaled
	if req.Model == "" {
		t.Error("OllamaRequest Model should not be empty")
	}

	if req.Prompt == "" {
		t.Error("OllamaRequest Prompt should not be empty")
	}

	if req.Stream != false {
		t.Error("OllamaRequest Stream should be false")
	}
}

func TestOllamaResponseJSON(t *testing.T) {
	resp := OllamaResponse{
		Model:    "qwen:1.8b",
		Response: "test response",
		Done:     true,
	}

	if resp.Model == "" {
		t.Error("OllamaResponse Model should not be empty")
	}

	if resp.Response == "" {
		t.Error("OllamaResponse Response should not be empty")
	}

	if resp.Done != true {
		t.Error("OllamaResponse Done should be true")
	}
}

func TestMaxLogSizeConstant(t *testing.T) {
	if MaxLogSize <= 0 {
		t.Error("MaxLogSize should be positive")
	}

	if MaxLogSize > 100*1024 {
		t.Errorf("MaxLogSize should be reasonable for small models, got %d", MaxLogSize)
	}
}

func TestMaxLinesConstant(t *testing.T) {
	if MaxLines <= 0 {
		t.Error("MaxLines should be positive")
	}
}

func TestOllamaDefaultURL(t *testing.T) {
	if OllamaDefaultURL != "http://localhost:11434" {
		t.Errorf("expected default URL http://localhost:11434, got %s", OllamaDefaultURL)
	}
}

func TestDefaultModel(t *testing.T) {
	if DefaultModel != "qwen:1.8b" {
		t.Errorf("expected default model qwen:1.8b, got %s", DefaultModel)
	}
}

func TestRequestTimeout(t *testing.T) {
	if RequestTimeout <= 0 {
		t.Error("RequestTimeout should be positive")
	}

	if RequestTimeout > 10*time.Minute {
		t.Errorf("RequestTimeout should be reasonable, got %v", RequestTimeout)
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestAnalyzerClientTimeout verifies client timeout is set
func TestAnalyzerClientTimeout(t *testing.T) {
	analyzer := NewLogAnalyzer()

	if analyzer.Client.Timeout <= 0 {
		t.Error("expected Client to have a timeout set")
	}

	if analyzer.Client.Timeout != RequestTimeout {
		t.Errorf("expected timeout %v, got %v", RequestTimeout, analyzer.Client.Timeout)
	}
}

// TestLogFilePath tests that file paths are handled correctly
func TestLogFilePath(t *testing.T) {
	// Create a temporary file with a specific name
	tmpDir, err := os.MkdirTemp("", "goscout_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "test.log")
	if err := os.WriteFile(logPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	//content, err := readLogFile(logPath)
	//if err != nil {
		t.Fatalf("readLogFile failed: %v", err)
	}

	if content != "test content" {
		t.Errorf("expected content 'test content', got %q", content)
	}
}
