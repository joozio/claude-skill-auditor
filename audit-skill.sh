#!/bin/bash
# Skill Security Audit Script
# Scans a skill directory or skills.sh package for suspicious patterns before installation.
#
# Usage:
#   audit-skill.sh <path-to-skill-dir>          # Audit a local skill directory
#   audit-skill.sh --from-skillssh <name>        # Download from skills.sh and audit
#   audit-skill.sh <path> --install              # Audit and install if LOW risk
#
# Exit codes: 0=LOW, 1=MEDIUM, 2=HIGH, 3=error

set -euo pipefail

SKILLS_DIR="$HOME/.claude/skills"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL=false
FROM_SKILLSSH=false
SKILL_PATH=""
FINDINGS=()
RISK_SCORE=0

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install) INSTALL=true; shift ;;
        --from-skillssh) FROM_SKILLSSH=true; shift; SKILL_NAME="$1"; shift ;;
        *) SKILL_PATH="$1"; shift ;;
    esac
done

# Download from skills.sh if requested
if $FROM_SKILLSSH; then
    echo -e "${CYAN}Downloading skill '$SKILL_NAME' from skills.sh to temp...${NC}"
    SKILL_PATH="$TEMP_DIR/skill"
    mkdir -p "$SKILL_PATH"
    # Use npx to download to temp location
    cd "$TEMP_DIR"
    npx skills add "$SKILL_NAME" --dir "$SKILL_PATH" 2>/dev/null || {
        echo -e "${RED}Failed to download skill from skills.sh${NC}"
        exit 3
    }
    cd - > /dev/null
fi

if [ -z "$SKILL_PATH" ] || [ ! -d "$SKILL_PATH" ]; then
    echo "Usage: audit-skill.sh <path-to-skill-dir> [--install]"
    echo "       audit-skill.sh --from-skillssh <owner/name> [--install]"
    exit 3
fi

echo -e "${CYAN}=== Skill Security Audit ===${NC}"
echo -e "Path: $SKILL_PATH"
echo ""

# --- Check 1: SKILL.md exists ---
if [ ! -f "$SKILL_PATH/SKILL.md" ]; then
    echo -e "${RED}[CRITICAL] No SKILL.md found - not a valid skill${NC}"
    exit 3
fi

SKILL_NAME_FROM_FILE=$(grep -m1 "^name:" "$SKILL_PATH/SKILL.md" | sed 's/name: *//' || echo "unknown")
echo -e "Skill: ${CYAN}$SKILL_NAME_FROM_FILE${NC}"
echo ""

# --- Check 2: File inventory ---
echo -e "${CYAN}--- File Inventory ---${NC}"
FILE_COUNT=$(find "$SKILL_PATH" -type f | wc -l | tr -d ' ')
echo "Total files: $FILE_COUNT"

# List non-markdown files (potential executables)
SUSPICIOUS_FILES=$(find "$SKILL_PATH" -type f \( -name "*.sh" -o -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.rb" -o -name "*.pl" -o -name "*.exe" -o -name "*.bin" -o -name "*.so" -o -name "*.dylib" \) 2>/dev/null || true)
if [ -n "$SUSPICIOUS_FILES" ]; then
    echo -e "${YELLOW}[WARN] Executable/script files found:${NC}"
    echo "$SUSPICIOUS_FILES" | while read f; do echo "  - $(basename $f)"; done
    RISK_SCORE=$((RISK_SCORE + 2))
    FINDINGS+=("Contains executable files")
fi

# Check for hidden files
HIDDEN_FILES=$(find "$SKILL_PATH" -name ".*" -not -name ".gitignore" -type f 2>/dev/null || true)
if [ -n "$HIDDEN_FILES" ]; then
    echo -e "${YELLOW}[WARN] Hidden files found:${NC}"
    echo "$HIDDEN_FILES" | while read f; do echo "  - $f"; done
    RISK_SCORE=$((RISK_SCORE + 3))
    FINDINGS+=("Contains hidden files")
fi
echo ""

# --- Check 3: Shell command patterns ---
echo -e "${CYAN}--- Shell Command Scan ---${NC}"

# Dangerous commands
for pattern in "curl " "wget " "bash -c" "sh -c" "eval " "exec(" "system(" "subprocess" "os.system" "child_process" "execSync" "spawn(" "| bash" "| sh"; do
    MATCHES=$(grep -rn "$pattern" "$SKILL_PATH" --include="*.md" --include="*.sh" --include="*.py" --include="*.js" --include="*.ts" 2>/dev/null | grep -v "^Binary" || true)
    if [ -n "$MATCHES" ]; then
        # Only flag if it's in executable context (not just documentation)
        EXEC_MATCHES=$(echo "$MATCHES" | grep -v "^.*\.md:" || true)
        DOC_MATCHES=$(echo "$MATCHES" | grep "^.*\.md:" || true)

        if [ -n "$EXEC_MATCHES" ]; then
            echo -e "${RED}[HIGH] '$pattern' in executable file:${NC}"
            echo "$EXEC_MATCHES" | head -3 | while read line; do echo "  $line"; done
            RISK_SCORE=$((RISK_SCORE + 5))
            FINDINGS+=("'$pattern' in executable file")
        fi
        if [ -n "$DOC_MATCHES" ]; then
            # Commands in markdown are less concerning (instructions for the agent)
            COUNT=$(echo "$DOC_MATCHES" | wc -l | tr -d ' ')
            echo -e "${YELLOW}[INFO] '$pattern' in docs ($COUNT occurrences) - review context${NC}"
            RISK_SCORE=$((RISK_SCORE + 1))
        fi
    fi
done
echo ""

# --- Check 4: Network / URL patterns ---
echo -e "${CYAN}--- Network Access Scan ---${NC}"

# URLs (excluding known safe domains)
URLS=$(grep -rnoE "https?://[^ \"')\`>]+" "$SKILL_PATH" 2>/dev/null | grep -v "github.com\|typefully.com\|claude.com\|anthropic.com\|npmjs.com\|skills.sh\|agentskills.io\|example.com\|localhost" || true)
if [ -n "$URLS" ]; then
    echo -e "${YELLOW}[WARN] External URLs found:${NC}"
    echo "$URLS" | head -10 | while read line; do echo "  $line"; done
    URL_COUNT=$(echo "$URLS" | wc -l | tr -d ' ')
    if [ "$URL_COUNT" -gt 5 ]; then
        RISK_SCORE=$((RISK_SCORE + 3))
        FINDINGS+=("$URL_COUNT external URLs found")
    else
        RISK_SCORE=$((RISK_SCORE + 1))
    fi
fi

# IP addresses
IPS=$(grep -rnoE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" "$SKILL_PATH" 2>/dev/null | grep -v "127.0.0.1\|0.0.0.0\|localhost" || true)
if [ -n "$IPS" ]; then
    echo -e "${RED}[HIGH] Hard-coded IP addresses:${NC}"
    echo "$IPS" | while read line; do echo "  $line"; done
    RISK_SCORE=$((RISK_SCORE + 5))
    FINDINGS+=("Hard-coded IP addresses")
fi
echo ""

# --- Check 5: Environment / credential access ---
echo -e "${CYAN}--- Credential Access Scan ---${NC}"

for pattern in "process.env" "os.environ" "os.getenv" "\$API_KEY" "\$SECRET" "\$TOKEN" "\$PASSWORD" "keychain" "credential" ".env "; do
    MATCHES=$(grep -rn "$pattern" "$SKILL_PATH" --include="*.sh" --include="*.py" --include="*.js" --include="*.ts" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
        echo -e "${YELLOW}[WARN] Credential pattern '$pattern' in scripts:${NC}"
        echo "$MATCHES" | head -3 | while read line; do echo "  $line"; done
        RISK_SCORE=$((RISK_SCORE + 2))
        FINDINGS+=("Credential access pattern: $pattern")
    fi
done
echo ""

# --- Check 6: Encoded / obfuscated content ---
echo -e "${CYAN}--- Obfuscation Scan ---${NC}"

# Base64 encoded strings (long ones are suspicious)
B64=$(grep -rnoE "[A-Za-z0-9+/]{50,}={0,2}" "$SKILL_PATH" 2>/dev/null | head -5 || true)
if [ -n "$B64" ]; then
    echo -e "${RED}[HIGH] Possible base64-encoded content:${NC}"
    echo "$B64" | while read line; do echo "  $line"; done
    RISK_SCORE=$((RISK_SCORE + 5))
    FINDINGS+=("Base64-encoded content detected")
fi

# Hex-encoded strings
HEX=$(grep -rnoE "\\\\x[0-9a-fA-F]{2}(\\\\x[0-9a-fA-F]{2}){10,}" "$SKILL_PATH" 2>/dev/null || true)
if [ -n "$HEX" ]; then
    echo -e "${RED}[HIGH] Hex-encoded content:${NC}"
    echo "$HEX" | head -3 | while read line; do echo "  $line"; done
    RISK_SCORE=$((RISK_SCORE + 5))
    FINDINGS+=("Hex-encoded content detected")
fi
echo ""

# --- Check 7: File system access outside skill dir ---
echo -e "${CYAN}--- File Access Scan ---${NC}"

for pattern in "/etc/" "/tmp/" "/var/" "\$HOME" "~/" "../../" "/Users/" "/root/"; do
    MATCHES=$(grep -rn "$pattern" "$SKILL_PATH" --include="*.sh" --include="*.py" --include="*.js" --include="*.ts" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
        echo -e "${YELLOW}[WARN] File access pattern '$pattern':${NC}"
        echo "$MATCHES" | head -3 | while read line; do echo "  $line"; done
        RISK_SCORE=$((RISK_SCORE + 2))
        FINDINGS+=("File access outside skill: $pattern")
    fi
done
echo ""

# --- Check 8: allowed-tools review ---
echo -e "${CYAN}--- Allowed Tools ---${NC}"
ALLOWED=$(grep "^allowed-tools:" "$SKILL_PATH/SKILL.md" 2>/dev/null || echo "none specified")
echo "Declared: $ALLOWED"

# Flag if Bash is allowed (gives shell access)
if echo "$ALLOWED" | grep -qi "bash"; then
    echo -e "${YELLOW}[INFO] Skill requests Bash access (shell execution)${NC}"
    RISK_SCORE=$((RISK_SCORE + 1))
fi
echo ""

# --- RISK ASSESSMENT ---
echo -e "${CYAN}==============================${NC}"
if [ $RISK_SCORE -le 3 ]; then
    RISK_LEVEL="LOW"
    RISK_COLOR=$GREEN
    EXIT_CODE=0
elif [ $RISK_SCORE -le 8 ]; then
    RISK_LEVEL="MEDIUM"
    RISK_COLOR=$YELLOW
    EXIT_CODE=1
else
    RISK_LEVEL="HIGH"
    RISK_COLOR=$RED
    EXIT_CODE=2
fi

echo -e "Risk Score: ${RISK_COLOR}$RISK_SCORE ($RISK_LEVEL)${NC}"
echo ""

if [ ${#FINDINGS[@]} -gt 0 ]; then
    echo "Findings:"
    for f in "${FINDINGS[@]}"; do
        echo "  - $f"
    done
    echo ""
fi

# --- INSTALL ---
if $INSTALL; then
    if [ "$RISK_LEVEL" = "HIGH" ]; then
        echo -e "${RED}BLOCKED: Will not auto-install HIGH risk skill.${NC}"
        echo "Review findings above and install manually if you trust it."
        exit 2
    fi

    DEST="$SKILLS_DIR/$SKILL_NAME_FROM_FILE"
    if [ -d "$DEST" ]; then
        echo -e "${YELLOW}Skill '$SKILL_NAME_FROM_FILE' already exists at $DEST${NC}"
        echo "Remove it first or use a different name."
        exit 3
    fi

    echo -e "${GREEN}Installing to $DEST ...${NC}"
    cp -r "$SKILL_PATH" "$DEST"
    echo -e "${GREEN}Installed successfully.${NC}"
fi

exit $EXIT_CODE
