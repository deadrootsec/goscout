# Troubleshooting

### No secrets found when expected

- Check that the file is being scanned (not excluded)
- Verify the pattern matches your secret format
- Try with `--list-patterns` to see available patterns
- Check file is readable and not too large (default 10MB)

### Too many false positives

- Use `--severity high` to focus on critical secrets
- Exclude specific files or directories with `--exclude-dirs` or `--exclude-files`
- Create a custom configuration for your project

### Slow scanning

- Increase `--max-size` if you're scanning large text files
- Exclude additional directories with `--exclude-dirs`
- Ensure you're not scanning network drives or slow storage

## Support

For issues, questions, or suggestions:

1. Check existing GitHub issues
2. Create a new issue with:
   - GoScout version (`--version`)
   - Go version (`go version`)
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
