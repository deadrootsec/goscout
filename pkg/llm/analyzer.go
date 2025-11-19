package llm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	OllamaDefaultURL = "http://localhost:11434"
	DefaultModel     = "qwen2.5:1.5b"
	RequestTimeout   = 30 * time.Minute
	MaxLogSize       = 250 * 1024
	MaxLines         = 5000
	ChunkLines       = 2000
)

// LogAnalyzer handles communication with Ollama for log analysis
type LogAnalyzer struct {
	OllamaURL string
	Model     string
	Client    *http.Client
}

// OllamaRequest represents a request to Ollama API
type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

// OllamaResponse represents a response from Ollama API
type OllamaResponse struct {
	Model    string `json:"model"`
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// AnalysisResult contains the analysis findings
type AnalysisResult struct {
	Findings string
	Model    string
	Duration time.Duration
}

// NewLogAnalyzer creates a new log analyzer with default settings
func NewLogAnalyzer() *LogAnalyzer {
	return &LogAnalyzer{
		OllamaURL: OllamaDefaultURL,
		Model:     DefaultModel,
		Client: &http.Client{
			Timeout: RequestTimeout,
		},
	}
}

// SetModel sets the model to use for analysis
func (la *LogAnalyzer) SetModel(model string) {
	la.Model = model
}

// SetOllamaURL sets the Ollama server URL
func (la *LogAnalyzer) SetOllamaURL(url string) {
	la.OllamaURL = url
}

// HealthCheck verifies that Ollama is running
func (la *LogAnalyzer) HealthCheck() error {
	req, err := http.NewRequest("GET", la.OllamaURL+"/api/tags", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := la.Client.Do(req)
	if err != nil {
		return fmt.Errorf("ollama server not responding at %s: %w", la.OllamaURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama server returned status code %d", resp.StatusCode)
	}

	return nil
}

// AnalyzeLogFileChunked reads a log file and analyzes it in chunks
func (la *LogAnalyzer) AnalyzeLogFileChunked(logPath string, scanSecrets bool) (string, error) {
	// Read log file
	file, err := os.Open(logPath)
	if err != nil {
		return "", fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	// Split file into chunks by lines
	chunks := make([]string, 0)
	var currentChunk strings.Builder
	var lineCount int

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		currentChunk.WriteString(line)
		currentChunk.WriteString("\n")
		lineCount++

		if lineCount >= ChunkLines {
			chunks = append(chunks, currentChunk.String())
			currentChunk.Reset()
			lineCount = 0
		}
	}

	// Add remaining lines as final chunk
	if currentChunk.Len() > 0 {
		chunks = append(chunks, currentChunk.String())
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading log file: %w", err)
	}

	if len(chunks) == 0 {
		return "", fmt.Errorf("log file is empty")
	}

	// Analyze each chunk
	var results strings.Builder
	for i, chunk := range chunks {
		fmt.Fprintf(os.Stderr, "📊 Processing chunk %d/%d...\n", i+1, len(chunks))

		prompt := buildChunkAnalysisPrompt(chunk, scanSecrets)
		result, err := la.queryOllama(prompt)
		if err != nil {
			return "", fmt.Errorf("failed to analyze chunk %d: %w", i+1, err)
		}

		results.WriteString(fmt.Sprintf("=== Chunk %d Summary ===\n", i+1))
		results.WriteString(result.Findings)
		results.WriteString("\n\n")
	}

	return results.String(), nil
}

func buildChunkAnalysisPrompt(logContent string, scanSecrets bool) string {
	if scanSecrets {
		return fmt.Sprintf(`Analyze this log chunk for secrets, errors and information.
Output only findings of secrets, errors or general data found, nothing else.

Log:
%s`, logContent)
	}
	return fmt.Sprintf(`Summarize this log chunk. Output only key information found in the logs, no suggestions or recommendations.

Log:
%s`, logContent)
}

// queryOllama sends the analysis prompt to Ollama and gets response
func (la *LogAnalyzer) queryOllama(prompt string) (*AnalysisResult, error) {
	reqBody := OllamaRequest{
		Model:  la.Model,
		Prompt: prompt,
		Stream: false,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", la.OllamaURL+"/api/generate", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	startTime := time.Now()
	resp, err := la.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query ollama: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var ollamaResp OllamaResponse
	if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	duration := time.Since(startTime)

	return &AnalysisResult{
		Findings: strings.TrimSpace(ollamaResp.Response),
		Model:    la.Model,
		Duration: duration,
	}, nil
}
