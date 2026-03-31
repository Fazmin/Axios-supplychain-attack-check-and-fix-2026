#!/usr/bin/env bash
# ============================================================================
# Axios Supply Chain Attack — Detection & Fix Script (macOS/Linux)
# ============================================================================
#
# Usage:
#   ./check_and_fix.sh                                  # Scan and fix current directory
#   ./check_and_fix.sh --path ~/projects                # Scan and fix all projects under a folder
#   ./check_and_fix.sh --path ~/projects --max-depth 2  # Limit folder depth
#   ./check_and_fix.sh --check-only                     # Only scan, do not modify anything
#   ./check_and_fix.sh --safe-version "1.13.7"          # Pin to a specific safe version
#   ./check_and_fix.sh --skip-system-checks             # Only run per-project checks
#
# ============================================================================

# ── Colors ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m'

# ── Defaults ────────────────────────────────────────────────────────────────

SCAN_PATH=""
MAX_DEPTH=10
SKIP_SYSTEM=false
CHECK_ONLY=false
SAFE_VERSION=""

# ── Parse arguments ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --path)               SCAN_PATH="$2"; shift 2 ;;
    --max-depth)          MAX_DEPTH="$2"; shift 2 ;;
    --check-only)         CHECK_ONLY=true; shift ;;
    --safe-version)       SAFE_VERSION="$2"; shift 2 ;;
    --skip-system-checks) SKIP_SYSTEM=true; shift ;;
    -h|--help)
      echo "Usage: $0 [--path <dir>] [--max-depth <n>] [--check-only] [--safe-version <ver>] [--skip-system-checks]"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Helpers ─────────────────────────────────────────────────────────────────

resolve_safe_version() {
  if [[ -n "$SAFE_VERSION" ]]; then
    echo "$SAFE_VERSION"
    return
  fi

  if command -v npm &>/dev/null; then
    local latest
    latest=$(npm view axios version 2>/dev/null || true)
    latest=$(echo "$latest" | tr -d '[:space:]')
    if [[ -n "$latest" && "$latest" != "1.14.1" && "$latest" != "0.30.4" ]]; then
      echo "$latest"
      return
    fi
  fi

  echo "1.14.0"
}

REPAIR_FIXED=false

repair_project() {
  local project_dir="$1"
  local version="$2"
  REPAIR_FIXED=false
  local fixed=false

  local pkg_json="$project_dir/package.json"
  if [[ -f "$pkg_json" ]]; then
    local tmp_file
    tmp_file=$(mktemp)
    sed -E 's/("axios"[[:space:]]*:[[:space:]]*")[^"]*(")/\1'"$version"'\2/g' "$pkg_json" > "$tmp_file"
    if ! cmp -s "$pkg_json" "$tmp_file"; then
      mv "$tmp_file" "$pkg_json"
      echo -e "    ${CYAN}[fix]       package.json: axios pinned to $version${NC}"
      fixed=true
    else
      rm -f "$tmp_file"
    fi
  fi

  if [[ -d "$project_dir/node_modules/axios" ]]; then
    rm -rf "$project_dir/node_modules/axios"
    echo -e "    ${CYAN}[fix]       Removed node_modules/axios${NC}"
    fixed=true
  fi

  if [[ -d "$project_dir/node_modules/plain-crypto-js" ]]; then
    rm -rf "$project_dir/node_modules/plain-crypto-js"
    echo -e "    ${CYAN}[fix]       Removed node_modules/plain-crypto-js${NC}"
    fixed=true
  fi

  if [[ -f "$project_dir/package-lock.json" ]]; then
    if grep -qE '1\.14\.1|0\.30\.4|plain-crypto-js' "$project_dir/package-lock.json"; then
      rm -f "$project_dir/package-lock.json"
      echo -e "    ${CYAN}[fix]       Removed compromised package-lock.json${NC}"
      fixed=true
    fi
  fi

  if [[ -f "$project_dir/yarn.lock" ]]; then
    if grep -qE '1\.14\.1|0\.30\.4|plain-crypto-js' "$project_dir/yarn.lock"; then
      rm -f "$project_dir/yarn.lock"
      echo -e "    ${CYAN}[fix]       Removed compromised yarn.lock${NC}"
      fixed=true
    fi
  fi

  if [[ "$fixed" == true ]]; then
    echo -e "    ${YELLOW}[fix]       >> Run 'npm install' to regenerate clean dependencies${NC}"
  fi

  REPAIR_FIXED=$fixed
}

PROJECT_FOUND=false
PROJECT_FIXED=false

check_project() {
  local project_dir="$1"
  local do_fix="$2"
  local fix_version="$3"
  PROJECT_FOUND=false
  PROJECT_FIXED=false

  echo ""
  echo -e "  ${WHITE}── $project_dir${NC}"
  echo ""

  # Check 1: package.json — does it even use axios?
  local pkg_json="$project_dir/package.json"
  if [[ -f "$pkg_json" ]]; then
    if ! grep -q '"axios"' "$pkg_json"; then
      echo -e "    ${GRAY}[axios]     SKIP: Project does not depend on axios${NC}"
      return
    fi
  fi

  # Check 2: Installed axios version via node_modules
  local axios_pkg_json="$project_dir/node_modules/axios/package.json"
  if [[ -f "$axios_pkg_json" ]]; then
    local axios_ver
    axios_ver=$(grep '"version"' "$axios_pkg_json" | head -1 | sed 's/.*: *"\([^"]*\)".*/\1/')
    if [[ "$axios_ver" =~ ^(1\.14\.1|0\.30\.4) ]]; then
      echo -e "    ${RED}[version]   !! AFFECTED: axios $axios_ver installed${NC}"
      PROJECT_FOUND=true
    else
      echo -e "    ${GREEN}[version]   OK: axios $axios_ver${NC}"
    fi
  else
    echo -e "    ${GRAY}[version]   SKIP: node_modules not present (run npm install first)${NC}"
  fi

  # Check 3: Lockfile
  if [[ -f "$project_dir/package-lock.json" ]]; then
    if grep -qE '1\.14\.1|0\.30\.4|plain-crypto-js' "$project_dir/package-lock.json"; then
      echo -e "    ${RED}[lockfile]  !! AFFECTED: Compromised reference in lockfile${NC}"
      PROJECT_FOUND=true
    else
      echo -e "    ${GREEN}[lockfile]  OK: Lockfile clean${NC}"
    fi
  elif [[ -f "$project_dir/yarn.lock" ]]; then
    if grep -qE '1\.14\.1|0\.30\.4|plain-crypto-js' "$project_dir/yarn.lock"; then
      echo -e "    ${RED}[lockfile]  !! AFFECTED: Compromised reference in yarn.lock${NC}"
      PROJECT_FOUND=true
    else
      echo -e "    ${GREEN}[lockfile]  OK: yarn.lock clean${NC}"
    fi
  else
    echo -e "    ${GRAY}[lockfile]  SKIP: No lockfile found${NC}"
  fi

  # Check 4: Malicious dependency on disk
  if [[ -d "$project_dir/node_modules/plain-crypto-js" ]]; then
    echo -e "    ${RED}[malware]   !! AFFECTED: plain-crypto-js EXISTS in node_modules${NC}"
    PROJECT_FOUND=true
  else
    echo -e "    ${GREEN}[malware]   OK: plain-crypto-js not found${NC}"
  fi

  # Auto-fix if compromise detected
  if [[ "$PROJECT_FOUND" == true && "$do_fix" == true ]]; then
    echo ""
    echo -e "    ${CYAN}[fix]       Applying automatic fixes...${NC}"
    repair_project "$project_dir" "$fix_version"
    PROJECT_FIXED=$REPAIR_FIXED
  fi

  if [[ "$PROJECT_FOUND" == true ]]; then
    if [[ "$PROJECT_FIXED" == true ]]; then
      echo -e "    ${YELLOW}[result]    !! COMPROMISED — fixes applied${NC}"
    else
      echo -e "    ${RED}[result]    !! COMPROMISED${NC}"
    fi
  else
    echo -e "    ${GREEN}[result]    CLEAN${NC}"
  fi
}

# ── Banner ──────────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Axios Supply Chain Attack - Check & Fix${NC}"
echo -e "${CYAN}============================================${NC}"

# ── Resolve safe version ───────────────────────────────────────────────────

DO_FIX=true
if [[ "$CHECK_ONLY" == true ]]; then
  DO_FIX=false
fi

RESOLVED_VERSION="1.14.0"

if [[ "$DO_FIX" == true ]]; then
  echo -e "  ${GRAY}Resolving safe axios version...${NC}"
  RESOLVED_VERSION=$(resolve_safe_version)
  echo -e "  ${GREEN}Safe version: $RESOLVED_VERSION${NC}"
else
  echo -e "  ${GRAY}Mode: Check only (no fixes will be applied)${NC}"
fi

# ── Discover projects ───────────────────────────────────────────────────────

if [[ -n "$SCAN_PATH" ]]; then
  SCAN_ROOT=$(cd "$SCAN_PATH" && pwd)
else
  SCAN_ROOT="$PWD"
fi

IS_SINGLE=true
if [[ -n "$SCAN_PATH" ]]; then
  IS_SINGLE=false
fi

if [[ "$IS_SINGLE" == true ]]; then
  echo -e "  ${GRAY}Scope: Single project ($SCAN_ROOT)${NC}"
else
  echo -e "  ${GRAY}Scope: Recursive scan (depth $MAX_DEPTH)${NC}"
  echo -e "  ${GRAY}Root:  $SCAN_ROOT${NC}"
fi

GLOBAL_FOUND=false
AFFECTED_PROJECTS=()
FIXED_PROJECTS=()
SCANNED_COUNT=0

if [[ "$IS_SINGLE" == true ]]; then
  SCANNED_COUNT=1
  check_project "$SCAN_ROOT" "$DO_FIX" "$RESOLVED_VERSION"
  if [[ "$PROJECT_FOUND" == true ]]; then
    GLOBAL_FOUND=true
    AFFECTED_PROJECTS+=("$SCAN_ROOT")
    if [[ "$PROJECT_FIXED" == true ]]; then
      FIXED_PROJECTS+=("$SCAN_ROOT")
    fi
  fi
else
  echo ""
  echo -e "  ${YELLOW}Discovering Node.js projects...${NC}"

  PROJECT_DIRS=()
  while IFS= read -r pj; do
    PROJECT_DIRS+=("$(dirname "$pj")")
  done < <(
    find "$SCAN_ROOT" -maxdepth "$MAX_DEPTH" -name "package.json" \
      -not -path "*/node_modules/*" \
      -not -path "*/.cache/*" \
      -not -path "*/.next/*" \
      2>/dev/null | sort
  )

  TOTAL=${#PROJECT_DIRS[@]}

  if [[ "$TOTAL" -eq 0 ]]; then
    echo -e "  ${GRAY}No Node.js projects found under $SCAN_ROOT${NC}"
  else
    echo -e "  ${CYAN}Found $TOTAL project(s)${NC}"
    echo ""
    echo -e "${GRAY}────────────────────────────────────────────${NC}"
    echo -e "  ${YELLOW}PROJECT SCAN${NC}"
    echo -e "${GRAY}────────────────────────────────────────────${NC}"

    for proj in "${PROJECT_DIRS[@]}"; do
      SCANNED_COUNT=$((SCANNED_COUNT + 1))
      check_project "$proj" "$DO_FIX" "$RESOLVED_VERSION"
      if [[ "$PROJECT_FOUND" == true ]]; then
        GLOBAL_FOUND=true
        AFFECTED_PROJECTS+=("$proj")
        if [[ "$PROJECT_FIXED" == true ]]; then
          FIXED_PROJECTS+=("$proj")
        fi
      fi
    done
  fi
fi

# ── System-wide checks ─────────────────────────────────────────────────────

if [[ "$SKIP_SYSTEM" != true ]]; then
  echo ""
  echo -e "${GRAY}────────────────────────────────────────────${NC}"
  echo -e "  ${YELLOW}SYSTEM CHECKS${NC}"
  echo -e "${GRAY}────────────────────────────────────────────${NC}"
  echo ""

  # RAT artifacts
  echo -e "  ${YELLOW}[RAT] Checking for RAT artifacts...${NC}"

  if [[ "$(uname)" == "Darwin" ]]; then
    if [[ -f "/Library/Caches/com.apple.act.mond" ]]; then
      echo -e "    ${RED}!! CRITICAL: macOS RAT found at /Library/Caches/com.apple.act.mond${NC}"
      ls -la "/Library/Caches/com.apple.act.mond"
      GLOBAL_FOUND=true
    else
      echo -e "    ${GREEN}OK: macOS RAT artifact not found${NC}"
    fi
  fi

  if [[ -f "/tmp/ld.py" ]]; then
    echo -e "    ${RED}!! CRITICAL: Linux RAT found at /tmp/ld.py${NC}"
    ls -la "/tmp/ld.py"
    GLOBAL_FOUND=true
  else
    echo -e "    ${GREEN}OK: Linux RAT artifact (/tmp/ld.py) not found${NC}"
  fi

  # C2 connections
  echo ""
  echo -e "  ${YELLOW}[C2] Checking for active C2 connections...${NC}"

  C2_HIT=""
  if command -v netstat &>/dev/null; then
    C2_HIT=$(netstat -an 2>/dev/null | grep "142.11.206.73" || true)
  elif command -v ss &>/dev/null; then
    C2_HIT=$(ss -tn 2>/dev/null | grep "142.11.206.73" || true)
  fi

  if [[ -n "$C2_HIT" ]]; then
    echo -e "    ${RED}!! CRITICAL: Active connection to C2 (142.11.206.73)${NC}"
    echo "    $C2_HIT"
    GLOBAL_FOUND=true
  else
    echo -e "    ${GREEN}OK: No active C2 connections${NC}"
  fi

  DNS_HIT=$(grep -r "sfrclak.com" /var/log/ 2>/dev/null | head -3 || true)
  if [[ -n "$DNS_HIT" ]]; then
    echo -e "    ${RED}!! WARNING: DNS queries to sfrclak.com found in system logs${NC}"
    GLOBAL_FOUND=true
  fi
fi

# ── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}============================================${NC}"

if [[ "$IS_SINGLE" != true ]]; then
  echo -e "  ${WHITE}Projects scanned:  $SCANNED_COUNT${NC}"
  if [[ ${#AFFECTED_PROJECTS[@]} -gt 0 ]]; then
    echo -e "  ${RED}Projects affected: ${#AFFECTED_PROJECTS[@]}${NC}"
  else
    echo -e "  ${GREEN}Projects affected: 0${NC}"
  fi
  if [[ "$DO_FIX" == true && ${#FIXED_PROJECTS[@]} -gt 0 ]]; then
    echo -e "  ${CYAN}Projects fixed:    ${#FIXED_PROJECTS[@]}${NC}"
  fi
  if [[ ${#AFFECTED_PROJECTS[@]} -gt 0 ]]; then
    echo ""
    echo -e "  ${RED}Affected:${NC}"
    for ap in "${AFFECTED_PROJECTS[@]}"; do
      fix_tag=""
      for fp in "${FIXED_PROJECTS[@]}"; do
        if [[ "$fp" == "$ap" ]]; then
          fix_tag=" (fixed)"
          break
        fi
      done
      if [[ -n "$fix_tag" ]]; then
        echo -e "    ${YELLOW}- $ap$fix_tag${NC}"
      else
        echo -e "    ${RED}- $ap${NC}"
      fi
    done
  fi
  echo ""
fi

if [[ "$GLOBAL_FOUND" == true ]]; then
  if [[ "$DO_FIX" == true && ${#FIXED_PROJECTS[@]} -gt 0 ]]; then
    echo -e "  ${CYAN}FIXES APPLIED${NC}"
    echo ""
    echo -e "  ${YELLOW}Next steps:${NC}"
    echo "  1. Run 'npm install' in each fixed project to regenerate lockfile"
    echo "  2. Rotate ALL credentials (npm tokens, cloud keys, deploy keys, etc.)"
    echo "  3. Block sfrclak.com and 142.11.206.73"
    echo "  4. If RAT found: FULL SYSTEM REBUILD"
  else
    echo -e "  ${RED}!! POTENTIAL COMPROMISE DETECTED${NC}"
    echo ""
    echo -e "  ${YELLOW}Remediation:${NC}"
    echo "  1. Re-run with auto-fix: ./check_and_fix.sh --path <folder>"
    echo "     Or manually: npm install axios@1.14.0 --save-exact"
    echo "  2. Remove node_modules and reinstall: rm -rf node_modules && npm ci"
    echo "  3. Rotate ALL credentials"
    echo "  4. Block sfrclak.com and 142.11.206.73"
    echo "  5. If RAT found: FULL SYSTEM REBUILD"
  fi
else
  echo -e "  ${GREEN}ALL CLEAR${NC}"
  echo ""
  echo "  Preventive: npm install axios@1.14.0 --save-exact"
  echo "  Set: npm config set min-release-age 3"
fi

echo -e "${CYAN}============================================${NC}"
echo ""
