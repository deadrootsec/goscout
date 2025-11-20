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
	return `Analyze the following detected secrets and provide a detailed security assessment.

For each secret finding, provide:
1. The type of secret (API key, password, token, private key, etc.)
2. Why it's a critical security risk
3. Potential impact if exploited
4. Step-by-step remediation actions
5. Prevention strategies for the future

Be specific and actionable. Focus on the security implications and immediate actions needed.

Detected Secrets:
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

// ComprehensiveSecretsAnalysisPrompt returns a prompt for analyzing multiple secrets together for a comprehensive report
func ComprehensiveSecretsAnalysisPrompt(secretsReport string) string {
	return `Review this comprehensive secrets scan report and provide a detailed analysis of security risks and remediation priorities.

SECRETS REPORT:
` + secretsReport + `

Provide:
1. Critical Risks (must be addressed immediately)
2. High-Priority Issues (address within 24 hours)
3. Medium-Priority Issues (address within 1 week)
4. Low-Priority Issues (address within 1 month)
5. Overall Risk Assessment
6. Top 3 Remediation Actions

Focus on actionable insights and severity ranking.`
}

// SecretsResumePrompt returns the prompt for generating a comprehensive security resume from all detected secrets
func SecretsResumePrompt(allSecretsAnalysis string) string {
	return `Based on the following security analysis of detected secrets, create a comprehensive executive summary report.

The report should include:
1. Overall Risk Assessment (Critical/High/Medium/Low)
2. Summary of Findings (what types of secrets were found and where)
3. Immediate Action Items (what needs to be done first)
4. Timeline for Remediation (short-term: 1-7 days, medium-term: 1-4 weeks, long-term: 1-3 months)
5. Prevention Strategy (how to prevent similar issues in the future)
6. Compliance Implications (GDPR, SOC 2, PCI-DSS, etc. if applicable)

Format the report as a professional security briefing suitable for technical and non-technical stakeholders.

Secrets Analysis Data:
` + allSecretsAnalysis
}

// AggregatedSecurityReportPrompt returns the prompt for generating a final security report from scanner results
func AggregatedSecurityReportPrompt(scannerFindings string) string {
	return `You are a senior security analyst. Create a detailed security assessment report based on the scanner findings below.

The report should provide:
1. Executive Summary
   - Total vulnerabilities found
   - Risk distribution (High/Medium/Low)
   - Most critical areas of concern

2. Detailed Findings
   - Categorized by severity and type
   - File locations and line numbers
   - Clear description of each issue

3. Risk Impact Analysis
   - Potential attack vectors
   - Business impact if exploited
   - Customer/regulatory implications

4. Remediation Roadmap
   - Priority 1: Critical issues (within 24-48 hours)
   - Priority 2: High issues (within 1 week)
   - Priority 3: Medium issues (within 2 weeks)
   - Priority 4: Low issues (within 1 month)

5. Prevention Measures
   - Code review best practices
   - Automation recommendations
   - Team training suggestions

6. Compliance Checklist
   - OWASP compliance
   - CWE mappings
   - Relevant regulations

Format as a professional report suitable for C-level executives and development teams.

Scanner Findings:
` + scannerFindings
}

// QuickAssessmentPrompt returns a prompt for a quick security assessment
func QuickAssessmentPrompt(content string) string {
	return `Quickly assess this content for immediate security threats. Provide a rapid evaluation in bullet points.

Focus on:
- Critical issues that need immediate attention
- Exposed credentials or sensitive data
- Obvious misconfigurations
- Quick wins for remediation

Be concise but specific.

Content:
` + content
}

// ContextualSecurityPrompt returns a prompt for analyzing secrets with full context
func ContextualSecurityPrompt(filename string, lineNumber int, secretType string, context string) string {
	return `Analyze this specific secret finding in context.

File: ` + filename + `
Line: ` + string(rune(lineNumber)) + `
Detected Type: ` + secretType + `

Context (surrounding code):
` + context + `

Provide:
1. Confirmation of the secret type
2. Severity assessment
3. Immediate exposure risks
4. Recommended remediation steps
5. Root cause analysis (how did this get committed?)

Be specific and actionable.`
}

// RemediationPlanPrompt returns a prompt for creating a detailed remediation plan
func RemediationPlanPrompt(allFindings string) string {
	return `Based on these security findings, create a detailed remediation plan.

For each critical finding:
1. Root cause explanation
2. Step-by-step fix instructions
3. Testing and verification steps
4. Prevention of reoccurrence

Organize by priority and effort required (quick wins first).

Findings:
` + allFindings
}
