package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FileExists checks if a file or directory exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsDirectory checks if the given path is a directory
func IsDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// GetAbsPath returns the absolute path, or error if path is invalid
func GetAbsPath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path for %s: %w", path, err)
	}
	return absPath, nil
}

// TruncateString truncates a string to a maximum length
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return "..."
	}
	return s[:maxLen-3] + "..."
}

// ContainsString checks if a string slice contains a value
func ContainsString(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// RemoveDuplicates removes duplicate strings from a slice
func RemoveDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, v := range slice {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}

	return result
}

// SanitizePath removes sensitive parts from file paths
func SanitizePath(path string) string {
	// Remove the home directory if present
	home, err := os.UserHomeDir()
	if err == nil && strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}

// HighlightMatch returns a highlighted version of a string match
func HighlightMatch(content string, match string) string {
	if len(match) > 40 {
		return match[:40] + "..."
	}
	return match
}

// ParseBytes parses a byte size string (e.g., "10MB", "1GB")
func ParseBytes(s string) (int64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))

	multipliers := map[string]int64{
		"B":  1,
		"KB": 1024,
		"MB": 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
		"TB": 1024 * 1024 * 1024 * 1024,
	}

	for unit, multiplier := range multipliers {
		if strings.HasSuffix(s, unit) {
			numStr := strings.TrimSuffix(s, unit)
			numStr = strings.TrimSpace(numStr)

			var num int64
			_, err := fmt.Sscanf(numStr, "%d", &num)
			if err != nil {
				return 0, fmt.Errorf("invalid size format: %s", s)
			}

			return num * multiplier, nil
		}
	}

	// Try parsing as plain number
	var num int64
	_, err := fmt.Sscanf(s, "%d", &num)
	if err != nil {
		return 0, fmt.Errorf("invalid size format: %s", s)
	}

	return num, nil
}

// FormatBytes converts bytes to human-readable format
func FormatBytes(bytes int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(bytes)

	for _, unit := range units {
		if value < 1024 {
			return fmt.Sprintf("%.2f %s", value, unit)
		}
		value /= 1024
	}

	return fmt.Sprintf("%.2f TB", value)
}

// NormalizePathSeparators converts path separators to forward slashes
func NormalizePathSeparators(path string) string {
	return strings.ReplaceAll(path, string(filepath.Separator), "/")
}

// IsTextFile checks if a file is likely a text file by examining its extension
func IsTextFile(filename string) bool {
	textExtensions := map[string]bool{
		".go":         true,
		".java":       true,
		".py":         true,
		".js":         true,
		".ts":         true,
		".jsx":        true,
		".tsx":        true,
		".json":       true,
		".yaml":       true,
		".yml":        true,
		".xml":        true,
		".html":       true,
		".css":        true,
		".sh":         true,
		".bash":       true,
		".txt":        true,
		".md":         true,
		".markdown":   true,
		".env":        true,
		".config":     true,
		".conf":       true,
		".cfg":        true,
		".ini":        true,
		".toml":       true,
		".sql":        true,
		".pl":         true,
		".rb":         true,
		".rs":         true,
		".php":        true,
		".c":          true,
		".cpp":        true,
		".h":          true,
		".hpp":        true,
		".cs":         true,
		".swift":      true,
		".kt":         true,
		".gradle":     true,
		".properties": true,
		".dockerfile": true,
		".gitignore":  true,
	}

	ext := strings.ToLower(filepath.Ext(filename))
	return textExtensions[ext]
}

// GetRelativePath returns the relative path or the absolute path if relative path fails
func GetRelativePath(targetPath, basePath string) string {
	relPath, err := filepath.Rel(basePath, targetPath)
	if err != nil {
		return targetPath
	}
	return relPath
}

// CleanPath removes redundant elements from a path
func CleanPath(path string) string {
	return filepath.Clean(path)
}
