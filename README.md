# GoScout - Universal Scout for Security Intelligence

GoScout is a fast and **completely local** universal scout tool for scanning your local machine, system logs, and codebases. It intelligently detects exposed secrets, sensitive patterns, and security concerns using both pattern matching and AI-powered analysis.

## Overview

GoScout goes beyond simple repository scanning. It's your personal security scout that can:
- 🔍 Scan local machines for sensitive data (coming soon)
- 📋 Analyze system logs for security anomalies
- 🗂️ Search repositories for exposed secrets and credentials
- 🤖 Use AI capabilities to detect secrets and analyze logs (coming soon)

## Features

✨ **Zero External Dependencies** - No data is sent anywhere. Everything runs locally.

🚀 **Fast Scanning** - Efficiently scans large codebases, logs, and file systems with intelligent filtering.

🎯 **Comprehensive Pattern Detection** - Detects 25+ types of secrets including:
- AWS credentials (Access Keys, Secret Keys, Session Tokens)
- API keys (Generic, Google, Firebase, Stripe, Twilio, etc.)
- Database credentials (PostgreSQL, MySQL, MongoDB)
- Private keys (RSA, OpenSSH, PGP, EC)
- GitHub/GitLab tokens
- JWT tokens
- Slack webhooks
- And more...

🤖 **AI-Powered Analysis** - Coming soon: Advanced detection and log analysis using machine learning

🔧 **Flexible Configuration** - Customize which directories, files, and patterns to scan.

📊 **Multiple Output Formats** - Text, JSON, and table formats for easy integration.

⚡ **Severity Filtering** - Focus on the most critical findings with high, medium, and low severity levels.

🔐 **Multi-Target Scanning** - Scan local machines, system logs, repositories, and more.

## Installation

### From Source

```bash
git clone https://github.com/deadroot/goscout.git
cd goscout
make install # automatically adds to /usr/local/bin
```

## Quick Start

### Basic Usage

Scan the current directory:
```bash
goscout
```

Scan a specific directory:
```bash
goscout /path/to/repo
```

Scan system logs:
```bash
goscout --logai /path/to/logfile.log --prompt "look for unauthorized access attempts, failed logins, and suspicious patterns"
```

### Examples

**List all available patterns:**
```bash
goscout --list-patterns
```

**Show version:**
```bash
goscout --version
```

**Output as JSON:**
```bash
goscout . --json > results.json
```

**Filter by severity:**
```bash
goscout . --severity high
```

**Exclude specific directories:**
```bash
goscout . --exclude-dirs node_modules --exclude-dirs .venv
```

**Exclude specific files:**
```bash
goscout . --exclude-files "*.lock" --exclude-files "package.json"
```

**Set maximum file size to scan (in bytes):**
```bash
goscout . --max-size 5242880  # 5MB
```

**Use table format:**
```bash
goscout . --format table
```

## Command Line Options

```
Usage:
  goscout [path] [flags]

Flags:
  -f, --format string         Output format: text, json, table (default: "text")
  -s, --max-size int64       Max file size to scan in bytes (default: 10485760 = 10MB)
      --exclude-dirs string   Additional directories to exclude (can be used multiple times)
      --exclude-files string  Additional files to exclude (can be used multiple times)
  -S, --severity string      Filter results by severity: high, medium, low
  -v, --version              Show version
      --json                  Output JSON format (shorthand for --format json)
      --list-patterns        List all available patterns
  -h, --help                 Show help message
```

## Detected Secret Types

### High Severity

- **AWS Credentials**
  - Access Key ID
  - Secret Access Key
  - Session Tokens

- **API Keys**
  - Generic API keys
  - Google API keys
  - Firebase keys
  - Stripe keys
  - Twilio keys

- **Database Credentials**
  - PostgreSQL passwords
  - MySQL passwords
  - MongoDB connection strings
  - Generic database URLs

- **Private Keys**
  - RSA private keys
  - OpenSSH private keys
  - PGP private keys
  - EC private keys

- **Authentication Tokens**
  - GitHub Personal Access Tokens
  - JWT tokens
  - Slack tokens

### Medium Severity

- Passwords in code
- Generic secret assignments
- Mailchimp API keys

### Low Severity

- Private IP addresses

## Output Formats

### Text Format (Default)

```
⚠️  Secrets Found!

High Severity: 3
Medium Severity: 1

Files scanned: 256
Files skipped: 45

─────────────────────────────────────────────────────

📄 /path/to/config.env

  Line 5: AWS Access Key ID
    🔴 AWS Access Key ID
    Content: aws_access_key_id=AKIAIOSFODNN7EXAMPLE
    Match: aws_access_key_id=AKIAIOSFODNN7EXAMPLE

  Line 12: Database Connection String
    🔴 Database Connection String
    Content: db_url=postgres://user:pass@localhost:5432/db
    Match: postgres://user:pass@localhost:5432/db
```

### JSON Format

```json
{
  "summary": {
    "total_matches": 3,
    "high_severity": 2,
    "medium_severity": 1,
    "low_severity": 0
  },
  "matches": [
    {
      "file_path": "/path/to/config.env",
      "line_number": 5,
      "pattern_name": "AWS Access Key ID",
      "severity": "high",
      "match": "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
      "line_content": "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
    }
  ],
  "stats": {
    "files_scanned": 256,
    "files_skipped": 45
  }
}
```

### Table Format

```
File                                              | Line            | Severity   | Pattern
──────────────────────────────────────────────────-+─────────────────+────────────+────────────────────
/path/to/config.env                              |               5 | high       | AWS Access Key ID
/path/to/database.yml                            |              12 | high       | Database Connection String
/path/to/secrets.json                            |               8 | medium     | Password in Code

Total matches: 3
Files scanned: 256
Files skipped: 45
```

## Default Exclusions

GoScout automatically excludes the following directories:

- `.git`, `.hg`, `.svn`, `.bzr` - Version control
- `node_modules` - Node.js dependencies
- `vendor` - Go/PHP dependencies
- `.venv`, `venv`, `env` - Python virtual environments
- `dist`, `build`, `target` - Build directories
- `.idea`, `.vscode`, `.DS_Store` - IDE files

And the following file patterns:

- `.gitignore`
- `.dockerignore`
- `package-lock.json`
- `yarn.lock`
- `go.sum`

## Exit Codes

- `0` - Scan completed successfully with no secrets found
- `1` - Scan completed but secrets were detected
- `2` - Error during scanning

## Use Cases

### Pre-commit Hook

Add this to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
goscout --severity high
if [ $? -ne 0 ]; then
    echo "Aborting commit: High severity secrets detected!"
    exit 1
fi
```

### CI/CD Integration

**GitHub Actions:**

```yaml
name: Secret Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      - name: Build GoScout
        run: go build -o goscout ./cmd/goscout/main.go
      - name: Scan for secrets
        run: ./goscout . --severity high
```

**GitLab CI:**

```yaml
scan_secrets:
  script:
    - go build -o goscout ./cmd/goscout/main.go
    - ./goscout . --severity high
```

### System Audit

```bash
#!/bin/bash
# audit.sh - Scan local machine for exposed secrets

HOME_PATH="/home/username"
OUTPUT_FILE="security_scan_$(date +%Y%m%d).json"

goscout "$HOME_PATH" --json > "$OUTPUT_FILE"

if [ $? -ne 0 ]; then
    echo "Potential security issues found! Check $OUTPUT_FILE"
    # Send alert or notification
fi
```


## Project Structure

```
.
├── cmd
│   └── main.go
├── go.mod
├── goscout
├── go.sum
├── LICENSE
├── Makefile
├── pkg
│   ├── llm
│   │   ├── analyzer.go
│   │   └── analyzer_test.go
│   ├── patterns
│   │   ├── patterns.go
│   │   └── patterns_test.go
│   ├── report
│   │   └── reporter.go
│   ├── scanner
│   │   ├── scanner.go
│   │   └── scanner_test.go
│   └── utils
│       ├── utils.go
│       └── utils_test.go
├── README.md
└── TROUBLESHOOTING.md                     
```

## Current Capabilities & Roadmap

### Current Features
- Pattern-based secret detection (25+ patterns)
- Fast file and directory scanning
- Multiple output formats
- Configurable exclusions
- Severity-based filtering

### Coming Soon
- 🤖 AI-powered secret detection
- 📊 Advanced log analysis with machine learning
- 🎯 Behavioral anomaly detection
- 🔔 Real-time monitoring capabilities
- 📈 Comprehensive reporting and visualization

## Current Limitations

- **Text Files Only**: Binary files are automatically skipped
- **Pattern-Based Detection**: May have false positives/negatives depending on patterns used
- **No Network Checking**: Does not verify if keys are actually active
- **Local Only**: By design, all scanning happens locally with no external services

## False Positives

GoScout may occasionally flag:

- Example code in documentation
- Dummy credentials in test files
- String patterns that match secret patterns but aren't actually secrets

Review flagged items carefully and add files to exclusion lists if needed.

## Security

GoScout is designed with security and privacy in mind:

- No internet connectivity required
- No data collection or transmission
- All scanning happens locally on your machine
- Open source for full transparency
- Run it with confidence on any codebase or system

## License

MIT License - See LICENSE file for details

## Disclaimer

GoScout is a pattern-matching and analysis tool and is not a guarantee that all secrets will be found. It should be used as one part of a comprehensive security strategy. Always perform thorough security reviews and follow best practices for secret management and system hardening.
