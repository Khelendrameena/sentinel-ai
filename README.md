# Sentinel AI

Automated vulnerability scanner for bug bounty. Maps the full attack surface,
matches Nuclei-style vulnerability templates, then uses AI to filter false
positives — so every finding is worth investigating.

## Pipeline

1. **Attack Surface**: subdomain enum (CT logs + DNS) → port scan → service detection
2. **Template Scan**: YAML vulnerability templates (XSS, SQLi, CVEs, misconfigs)
3. **AI Verify**: Jev decision model scores each finding for true-positive probability
4. **Report**: Ranked findings with evidence, severity, and reproduction steps

## Quick start

```bash
pip install -r requirements.txt
python -m sentinel.cli scan example.com -o report.json
```

With Jev for AI verification:
```bash
export JEV_API_KEY=xxx
python -m sentinel.cli scan example.com --ai-verify
```

## Templates

Add YAML templates in `templates/`:
```yaml
id: xss-reflected
severity: high
match:
  type: reflect
  param: q
payload: "<script>alert(1)</script>"
```
