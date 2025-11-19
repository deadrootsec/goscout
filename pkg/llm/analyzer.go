package llm

import (
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
	DefaultModel     = "qiuchen/qwen1.5-1.8b-chat:latest"
	RequestTimeout   = 30 * time.Minute
	MaxLogSize       = 250 * 1024
	MaxLines         = 5000
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

// AnalyzeLogFile reads a log file and analyzes it with the LLM
func (la *LogAnalyzer) AnalyzeLogFile(logPath, userPrompt string) (*AnalysisResult, error) {
	// Read log file
	logContent, err := readLogFile(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read log file: %w", err)
	}

	// Build the prompt for analysis
	prompt := buildAnalysisPrompt(userPrompt, logContent)

	// Send request to Ollama
	result, err := la.queryOllama(prompt)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// readLogFile reads a log file, limiting size for small model performance
func readLogFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Read file content with size limit
	data, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	content := string(data)

	// If file is too large, use last MaxLogSize bytes
	if len(content) > MaxLogSize {
		content = content[len(content)-MaxLogSize:]
		fmt.Fprintf(os.Stderr, "⚠️  Log file truncated to last 15KB for performance\n")
	}

	return content, nil
}

func buildAnalysisPrompt(userPrompt, logContent string) string {
	return fmt.Sprintf(`Analyze this log. Task: %s

Instructions:
- Output ONLY information related to the task
- Be concise and direct
- No extra commentary

Log:
%s`, userPrompt, logContent)
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
