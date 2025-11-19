package llm

// LogAnalysisPrompt returns the prompt for analyzing log chunks
func LogAnalysisPrompt(logContent string) string {
	return `You must respond in English only. Analyze this log chunk and provide a concise summary of key information found.

Focus on:
- Errors and warnings
- Important events or state changes
- Performance issues
- Security-related messages

Do not provide suggestions, recommendations, or improvements. Only report what is in the logs.

Log:
` + logContent
}

// SecretsAnalysisPrompt returns the prompt for analyzing potential secrets
func SecretsAnalysisPrompt(fileContent string) string {
	return `Analyze the following code/config content and identify potential secrets, API keys, tokens, or sensitive information that should not be exposed.

For each finding, provide:
1. The type of secret (API key, password, token, etc.)
2. Why it's a security risk
3. Recommendation for remediation

Code/Config:
` + fileContent
}

// CodeSecurityPrompt returns the prompt for general code security analysis
func CodeSecurityPrompt(codeContent string) string {
	return `Review this code for security vulnerabilities, misconfigurations, and best practice violations.

Identify:
- Hard-coded credentials or sensitive data
- Insecure configurations
- Vulnerable patterns or practices
- Compliance issues

Respond only with findings, no recommendations.

Code:
` + codeContent
}

// ConfigAnalysisPrompt returns the prompt for analyzing configuration files
func ConfigAnalysisPrompt(configContent string) string {
	return `Analyze this configuration file for security and compliance issues.

Look for:
- Exposed credentials or secrets
- Insecure settings
- Missing security controls
- Best practice violations

Report findings concisely.

Config:
` + configContent
}
