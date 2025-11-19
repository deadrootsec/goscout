package llm

import (
	"testing"
	"time"
)

func TestNewAnalyzer(t *testing.T) {
	analyzer := NewAnalyzer()

	if analyzer.OllamaURL != OllamaDefaultURL {
		t.Errorf("expected OllamaURL %s, got %s", OllamaDefaultURL, analyzer.OllamaURL)
	}

	if analyzer.Model != DefaultModel {
		t.Errorf("expected Model %s, got %s", DefaultModel, analyzer.Model)
	}

	if analyzer.ChunkLines != DefaultChunkLines {
		t.Errorf("expected ChunkLines %d, got %d", DefaultChunkLines, analyzer.ChunkLines)
	}

	if analyzer.Client == nil {
		t.Error("expected Client to be initialized, got nil")
	}
}

func TestSetModel(t *testing.T) {
	analyzer := NewAnalyzer()
	newModel := "phi:2.7b"
	analyzer.SetModel(newModel)

	if analyzer.Model != newModel {
		t.Errorf("expected Model %s, got %s", newModel, analyzer.Model)
	}
}

func TestSetOllamaURL(t *testing.T) {
	analyzer := NewAnalyzer()
	newURL := "http://192.168.1.100:11434"
	analyzer.SetOllamaURL(newURL)

	if analyzer.OllamaURL != newURL {
		t.Errorf("expected OllamaURL %s, got %s", newURL, analyzer.OllamaURL)
	}
}

func TestSetChunkLines(t *testing.T) {
	analyzer := NewAnalyzer()
	newChunkLines := 5000
	analyzer.SetChunkLines(newChunkLines)

	if analyzer.ChunkLines != newChunkLines {
		t.Errorf("expected ChunkLines %d, got %d", newChunkLines, analyzer.ChunkLines)
	}
}

func TestSetChunkLinesNegative(t *testing.T) {
	analyzer := NewAnalyzer()
	original := analyzer.ChunkLines
	analyzer.SetChunkLines(-1)

	if analyzer.ChunkLines != original {
		t.Errorf("expected ChunkLines to remain %d with negative input, got %d", original, analyzer.ChunkLines)
	}
}

func TestOllamaRequestJSON(t *testing.T) {
	req := OllamaRequest{
		Model:  "qwen:1.5b",
		Prompt: "test prompt",
		Stream: false,
	}

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
		Model:    "qwen:1.5b",
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

func TestAnalysisResultFields(t *testing.T) {
	result := &AnalysisResult{
		Findings: "test findings",
		Model:    "qwen:1.5b",
		Duration: 5 * time.Second,
	}

	if result.Findings != "test findings" {
		t.Errorf("expected Findings %q, got %q", "test findings", result.Findings)
	}

	if result.Model != "qwen:1.5b" {
		t.Errorf("expected Model %q, got %q", "qwen:1.5b", result.Model)
	}

	if result.Duration != 5*time.Second {
		t.Errorf("expected Duration 5s, got %v", result.Duration)
	}
}

func TestOllamaDefaultURL(t *testing.T) {
	if OllamaDefaultURL != "http://localhost:11434" {
		t.Errorf("expected default URL http://localhost:11434, got %s", OllamaDefaultURL)
	}
}

func TestDefaultModel(t *testing.T) {
	if DefaultModel != "qwen2.5:1.5b" {
		t.Errorf("expected default model qwen2.5:1.5b, got %s", DefaultModel)
	}
}

func TestDefaultChunkLines(t *testing.T) {
	if DefaultChunkLines != 2000 {
		t.Errorf("expected default chunk lines 2000, got %d", DefaultChunkLines)
	}
}

func TestRequestTimeout(t *testing.T) {
	if RequestTimeout <= 0 {
		t.Error("RequestTimeout should be positive")
	}

	if RequestTimeout != 30*time.Minute {
		t.Errorf("expected RequestTimeout 30m, got %v", RequestTimeout)
	}
}

func TestAnalyzerClientTimeout(t *testing.T) {
	analyzer := NewAnalyzer()

	if analyzer.Client.Timeout <= 0 {
		t.Error("expected Client to have a timeout set")
	}

	if analyzer.Client.Timeout != RequestTimeout {
		t.Errorf("expected timeout %v, got %v", RequestTimeout, analyzer.Client.Timeout)
	}
}
