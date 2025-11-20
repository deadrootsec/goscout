package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	OllamaDefaultURL  = "http://localhost:11434"
	DefaultModel      = "qwen3:1.7b"
	DefaultChunkLines = 2000
	RequestTimeout    = 30 * time.Minute
)

// Analyzer handles communication with Ollama for analysis
type Analyzer struct {
	OllamaURL  string
	Model      string
	ChunkLines int
	Client     *http.Client
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

// SecretAnalysisResult contains detailed analysis of a secret finding
type SecretAnalysisResult struct {
	SecretType      string
	RiskLevel       string
	Analysis        string
	Recommendations string
	Model           string
	Duration        time.Duration
}

// NewAnalyzer creates a new analyzer with default settings
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		OllamaURL:  OllamaDefaultURL,
		Model:      DefaultModel,
		ChunkLines: DefaultChunkLines,
		Client: &http.Client{
			Timeout: RequestTimeout,
		},
	}
}

// SetModel sets the model to use for analysis
func (a *Analyzer) SetModel(model string) {
	a.Model = model
}

// SetChunkLines sets the number of lines per chunk for analysis
func (a *Analyzer) SetChunkLines(lines int) {
	if lines > 0 {
		a.ChunkLines = lines
	}
}

// SetOllamaURL sets the Ollama server URL
func (a *Analyzer) SetOllamaURL(url string) {
	a.OllamaURL = url
}

// HealthCheck verifies that Ollama is running
func (a *Analyzer) HealthCheck() error {
	req, err := http.NewRequest("GET", a.OllamaURL+"/api/tags", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := a.Client.Do(req)
	if err != nil {
		return fmt.Errorf("ollama server not responding at %s: %w", a.OllamaURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama server returned status code %d", resp.StatusCode)
	}

	return nil
}

// Query sends a prompt to Ollama and gets the response
func (a *Analyzer) Query(prompt string) (*AnalysisResult, error) {
	reqBody := OllamaRequest{
		Model:  a.Model,
		Prompt: prompt,
		Stream: false,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", a.OllamaURL+"/api/generate", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	startTime := time.Now()
	resp, err := a.Client.Do(req)
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
		Findings: ollamaResp.Response,
		Model:    a.Model,
		Duration: duration,
	}, nil
}

// AnalyzeSecrets sends detected secrets to the analyzer for detailed analysis
// It returns a structured analysis of the security implications
func (a *Analyzer) AnalyzeSecrets(secretContent string) (*SecretAnalysisResult, error) {
	prompt := SecretsAnalysisPrompt(secretContent)

	result, err := a.Query(prompt)
	if err != nil {
		return nil, err
	}

	return &SecretAnalysisResult{
		Analysis: result.Findings,
		Model:    a.Model,
		Duration: result.Duration,
	}, nil
}

// AnalyzeLogs sends log content to the analyzer for security analysis
func (a *Analyzer) AnalyzeLogs(logContent string) (*AnalysisResult, error) {
	prompt := LogAnalysisPrompt(logContent)
	return a.Query(prompt)
}

// AnalyzeCode sends code content to the analyzer for security analysis
func (a *Analyzer) AnalyzeCode(codeContent string) (*AnalysisResult, error) {
	prompt := CodeSecurityPrompt(codeContent)
	return a.Query(prompt)
}

// AnalyzeConfig sends configuration content to the analyzer for security analysis
func (a *Analyzer) AnalyzeConfig(configContent string) (*AnalysisResult, error) {
	prompt := ConfigAnalysisPrompt(configContent)
	return a.Query(prompt)
}

// AnalyzeWithCustomPrompt sends custom prompt content to the analyzer
func (a *Analyzer) AnalyzeWithCustomPrompt(customPrompt string) (*AnalysisResult, error) {
	return a.Query(customPrompt)
}
