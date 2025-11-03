# 🔍 GitHub Workflow Auditor

A GitHub Action to scan workflow files (`.github/workflows/*.yml`) for:

- 🛡️ Security risks (unrestricted permissions, unpinned actions, missing security best practices)
- 🚀 Performance improvements (cache usage, shallow git fetch, concurrency)
- 🤖 Optional AI-based insights using OpenRouter LLM for deeper static analysis

---

## 📦 Features

- Detects:
  - Unpinned or outdated actions
  - Overly permissive credentials
  - Missing or weak `permissions`, `concurrency`, or caching
  - Full `git` fetches where not needed
- SARIF output for GitHub Security tab 📊
- Markdown report for easy review
- Optional AI analysis for advanced recommendations
- Organization-wide or single-repo scanning
- Customizable severity threshold and exclusion patterns
- Automatic upload of SARIF to CodeQL (optional)

---

## 🚀 Usage

### Basic: Scan this repository

```yaml
# .github/workflows/audit.yml
name: Audit workflows
on:
  workflow_dispatch:
  push:
    paths:
      - ".github/workflows/**"

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run auditor
        uses: wvxi/gh-wf-audit@main
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          output_format: both
          ai_enabled: true
          ai_openrouter_token: ${{ secrets.OPENROUTER_API_KEY }}
```

### Organization-wide scan

```yaml
# .github/workflows/org-audit.yml
on: workflow_dispatch

permissions:
  contents: read
  security-events: write

jobs:
  audit-org:
    runs-on: ubuntu-latest
    steps:
      - name: Run auditor on org
        uses: wvxi/gh-wf-audit@main
        with:
          github_token: ${{ secrets.ORG_READ_PAT }}
          org: your-org-name
          output_format: both
          fail_on_findings: true
          ai_enabled: true
          ai_openrouter_token: ${{ secrets.OPENROUTER_API_KEY }}
```

---

## ⚙️ Inputs

| Name                  | Description                                                           | Default                              |
|-----------------------|-----------------------------------------------------------------------|--------------------------------------|
| `github_token`        | GitHub token with repo/org read access                                | required                             |
| `org`                 | Organization to scan (scans all repos, requires PAT)                  | `""`                                 |
| `repo`                | Repository to scan (`owner/name`). Defaults to the checked-out repo   | `""`                                 |
| `include_archived`    | Include archived repos in org scan                                    | `false`                              |
| `exclude`             | Comma-separated patterns to exclude                                   | `""`                                 |
| `fail_on_findings`    | Fail job if issues are found                                          | `false`                              |
| `output_format`       | `"md"`, `"sarif"`, or `"both"`                                   | `"both"`                             |
| `sarif_to_codeql`     | Upload SARIF to CodeQL for autofix suggestions (true/false)           | `"false"`                            |
| `min_severity`        | Minimum severity to report (`low`, `medium`, `high`)                  | `"low"`                              |
| `ai_enabled`          | Enable AI-enhanced static analysis                                    | `false`                              |
| `ai_provider`         | AI provider. `"hf"` (Hugging Face) only for now                     | `"hf"`                               |
| `ai_model`            | Model ID (e.g. `mistralai/Mistral-7B-Instruct-v0.3`)                  | `"mistralai/Mistral-7B-Instruct-v0.3"`|
| `ai_openrouter_token` | OpenRouter access token (alternative to HF, free tier supported)      | `""`                                 |
| `ai_max_tokens`       | Max tokens for AI response                                            | `400`                                |
| `ai_temperature`      | Sampling temperature for AI                                           | `0.1`                                |

---

## 📤 Outputs

- SARIF: `workflow-audit.sarif`
- Markdown: `workflow-audit-report.md`
- Annotations in PRs and push UI

---

## 🧠 AI Integration

- Uses open-source LLMs (OpenRouter) for advanced insights and suggestions
- Models supported: Any OpenRouter text-generation model supporting `max_new_tokens`
- Get a free OpenRouter API key at https://openrouter.ai/

---

## 🛠 Development

```sh
pip install -r requirements.txt
python audit.py
# To test the AI advisor independently:
python advise.py
```

---
