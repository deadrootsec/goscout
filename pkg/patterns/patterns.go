package patterns

import "regexp"

// Pattern represents a secret pattern to search for
type Pattern struct {
	Name        string
	Description string
	Regex       *regexp.Regexp
	Severity    string // "high", "medium", "low"
}

// SecretPatterns contains all the patterns to search for secrets
var SecretPatterns = []Pattern{
	{
		Name:        "AWS Access Key",
		Description: "AWS Access Key ID",
		Regex:       regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
		Severity:    "high",
	},
	{
		Name:        "AWS Secret Key",
		Description: "AWS Secret Access Key",
		Regex:       regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?`),
		Severity:    "high",
	},
	{
		Name:        "Private SSH Key",
		Description: "Private SSH Key",
		Regex:       regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----`),
		Severity:    "high",
	},
	{
		Name:        "GitHub Token",
		Description: "GitHub Personal Access Token",
		Regex:       regexp.MustCompile(`(?i)github[_-]?token\s*=\s*['\"]?([a-z0-9]{40})['\"]?`),
		Severity:    "high",
	},
	{
		Name:        "Generic API Key",
		Description: "Generic API Key Pattern",
		Regex:       regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9\-_]{20,})['\"]?`),
		Severity:    "high",
	},
	{
		Name:        "Database Password",
		Description: "Database Connection String with Password",
		Regex:       regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]+)['\"]`),
		Severity:    "high",
	},
	{
		Name:        "JWT Token",
		Description: "JWT Token Pattern",
		Regex:       regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
		Severity:    "high",
	},
	{
		Name:        "Slack Token",
		Description: "Slack API Token",
		Regex:       regexp.MustCompile(`(?i)xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-z0-9_-]*`),
		Severity:    "high",
	},
	{
		Name:        "Firebase Key",
		Description: "Firebase API Key",
		Regex:       regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		Severity:    "high",
	},
	{
		Name:        "Heroku API Key",
		Description: "Heroku API Key",
		Regex:       regexp.MustCompile(`(?i)heroku[_-]?api[_-]?key\s*[=:]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]?`),
		Severity:    "high",
	},
	{
		Name:        "PagerDuty Token",
		Description: "PagerDuty Integration Key",
		Regex:       regexp.MustCompile(`(?i)pagerduty[_-]?token\s*[=:]\s*['\"]?([a-z0-9]{20})['\"]?`),
		Severity:    "medium",
	},
	{
		Name:        "Generic Secret",
		Description: "Generic Secret Variable",
		Regex:       regexp.MustCompile(`(?i)(secret|token|passwd|password)\s*[=:]\s*['\"]([^'\"]+)['\"]`),
		Severity:    "medium",
	},
	{
		Name:        "Private Key File",
		Description: "Private Key File Reference",
		Regex:       regexp.MustCompile(`(?i)(private_key|private.key|id_rsa|id_ed25519)\s*[=:]\s*['\"]?([^'\"]+\.key)['\"]?`),
		Severity:    "high",
	},
	{
		Name:        "Basic Auth",
		Description: "HTTP Basic Authentication",
		Regex:       regexp.MustCompile(`(?i)(http|https)://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@`),
		Severity:    "high",
	},
	{
		Name:        "Stripe Key",
		Description: "Stripe API Key",
		Regex:       regexp.MustCompile(`(?i)stripe[_-]?(api|secret|public)[_-]?key\s*[=:]\s*['\"]?(sk_live_[a-zA-Z0-9]{24,}|pk_live_[a-zA-Z0-9]{24,})['\"]?`),
		Severity:    "high",
	},
}

// GetPatterns returns all secret patterns
func GetPatterns() []Pattern {
	return SecretPatterns
}

// GetPatternsByName returns patterns matching the given name (partial match)
func GetPatternsByName(name string) []Pattern {
	var matched []Pattern
	for _, p := range SecretPatterns {
		if p.Name == name {
			matched = append(matched, p)
		}
	}
	return matched
}

// GetPatternsBySeverity returns patterns matching the given severity
func GetPatternsBySeverity(severity string) []Pattern {
	var matched []Pattern
	for _, p := range SecretPatterns {
		if p.Severity == severity {
			matched = append(matched, p)
		}
	}
	return matched
}
