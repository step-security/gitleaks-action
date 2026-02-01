# Gitleaks Action

<p align="left">
    <a href="https://github.com/step-security/gitleaks-action">
        <img alt="gitleaks badge" src="https://img.shields.io/badge/protected%20by-gitleaks-blue">
    </a>
</p>

A GitHub Action for detecting and preventing hardcoded secrets in your repositories. This action integrates Gitleaks - a powerful SAST (Static Application Security Testing) tool - directly into your CI/CD pipeline to catch leaked credentials before they reach production.

## Features

- 🔍 Scans for hardcoded secrets (API keys, passwords, tokens)
- 💬 Automatic PR comments with detailed leak information
- 📊 Rich job summaries with actionable insights
- 🔄 Supports multiple trigger events (push, PR, schedule, manual)
- ⚙️ Highly configurable with environment variables
- 🚀 Fast execution with intelligent caching

## Quick Start

Add this workflow to your repository at `.github/workflows/secrets-scan.yml`:

```yaml
name: Secret Detection
on:
  pull_request:
  push:
  workflow_dispatch:
  schedule:
    - cron: "0 4 * * *"

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Gitleaks
        uses: step-security/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | Automatically provided by GitHub Actions. Required for API operations and PR commenting. [Learn more](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#about-the-github_token-secret) |

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GITLEAKS_VERSION` | `8.24.3` | Specific Gitleaks version or `latest` for the newest release |
| `GITLEAKS_CONFIG` | (none) | Path to custom Gitleaks configuration file |
| `GITLEAKS_ENABLE_COMMENTS` | `true` | Enable/disable automatic PR comments |
| `GITLEAKS_ENABLE_SUMMARY` | `true` | Enable/disable job summary generation |
| `GITLEAKS_ENABLE_UPLOAD_ARTIFACT` | `true` | Enable/disable SARIF artifact upload |
| `GITLEAKS_NOTIFY_USER_LIST` | (none) | Comma-separated list of GitHub usernames to notify (e.g., `@alice,@bob`) |
| `BASE_REF` | (auto) | Override the base commit reference for scanning |

### Example: Custom Configuration

```yaml
- name: Run Gitleaks with custom config
  uses: step-security/gitleaks-action@v1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITLEAKS_VERSION: latest
    GITLEAKS_CONFIG: .github/gitleaks.toml
    GITLEAKS_NOTIFY_USER_LIST: "@security-team,@devops"
```

## How It Works

### Event-Based Scanning

**Push Events**: Scans all commits in the push

**Pull Requests**: Scans only the commits in the PR and adds inline comments

**Scheduled Runs**: Full repository scan

**Manual Triggers**: On-demand full scan

### Detection Process

1. **Download**: Fetches the Gitleaks binary (cached for performance)
2. **Scan**: Analyzes git history for secret patterns
3. **Report**: Generates SARIF output with findings
4. **Notify**: Posts PR comments and creates job summaries
5. **Artifact**: Uploads results for further analysis

## Custom Gitleaks Configuration

You have two options for customizing detection rules:

### Option 1: Configuration File

Set the `GITLEAKS_CONFIG` environment variable:

```yaml
env:
  GITLEAKS_CONFIG: path/to/config.toml
```

### Option 2: Auto-Detection

Create a `gitleaks.toml` file in your repository root. The action will automatically detect and use it.

See the [official Gitleaks configuration documentation](https://github.com/zricethezav/gitleaks#configuration) for configuration options.

## Privacy & Security

**Q: Does this action send data externally?**

A: No. All scanning happens within your GitHub Actions runner. Your code never leaves GitHub's infrastructure. The action is fully self-contained.

**Q: What data is stored?**

A: Scan results are stored as GitHub Actions artifacts and optionally in PR comments. All data remains within your GitHub environment.

## GitHub Code Scanning Integration

While this action can upload SARIF files for GitHub Code Scanning, **we recommend against using it as a primary security tool** in that context.

**Why?** If a secret is committed and then removed in a later commit, GitHub's security dashboard will mark the issue as resolved, even though the secret remains in git history. The proper remediation requires:

1. Rotating the compromised credential
2. Optionally rewriting git history to remove the secret entirely

Use this action for **prevention and detection**, not just compliance reporting.

## Troubleshooting

### False Positives

Add fingerprints to `.gitleaksignore` in your repository:

```bash
# The action will provide the exact fingerprint in PR comments
echo "commit:file:rule:line" >> .gitleaksignore
```

### No Commits to Scan

If you see "No commits to scan", ensure your checkout action uses `fetch-depth: 0` to fetch the full git history.

### Permission Errors

Ensure the `GITHUB_TOKEN` has sufficient permissions. The default token should work for most cases.

## License

MIT License - See [LICENSE](LICENSE) for details.
