#!/usr/bin/env bash
###############################################################################
# lib/common.sh — Shared functions for SentinelBash modules
#
# Every module sources this file to get:
#   - Consistent finding emission (JSON lines written to a shared findings file)
#   - Color-coded console output
#   - Severity scoring helpers
###############################################################################

# Guard against being sourced twice
if [[ -n "${SENTINEL_COMMON_LOADED:-}" ]]; then
    return 0
fi
SENTINEL_COMMON_LOADED=1

# --- Colors -------------------------------------------------------------
readonly C_RED='\033[0;31m'
readonly C_YELLOW='\033[0;33m'
readonly C_GREEN='\033[0;32m'
readonly C_BLUE='\033[0;34m'
readonly C_RESET='\033[0m'

# --- Findings collection --------------------------------------------------
# Findings are appended as single-line JSON objects to $SENTINEL_FINDINGS_FILE
# (JSON Lines format) so multiple modules can write concurrently without
# needing to parse/re-serialize a shared array.

: "${SENTINEL_FINDINGS_FILE:=/tmp/sentinelbash_findings.jsonl}"

# json_escape STRING — escape a string for safe embedding in JSON
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# emit_finding MODULE SEVERITY TYPE DESCRIPTION [EVIDENCE]
# Writes one finding as a JSON line and prints a colored console line.
emit_finding() {
    local module="$1" severity="$2" type="$3" description="$4" evidence="${5:-}"

    local color="$C_BLUE"
    case "$severity" in
        critical) color="$C_RED" ;;
        high)     color="$C_RED" ;;
        medium)   color="$C_YELLOW" ;;
        low)      color="$C_GREEN" ;;
        info)     color="$C_BLUE" ;;
    esac

    printf "${color}[%s]${C_RESET} %-10s %s\n" "${severity^^}" "$module" "$description" >&2

    {
        printf '{'
        printf '"module":"%s",' "$(json_escape "$module")"
        printf '"severity":"%s",' "$(json_escape "$severity")"
        printf '"type":"%s",' "$(json_escape "$type")"
        printf '"description":"%s"' "$(json_escape "$description")"
        if [[ -n "$evidence" ]]; then
            printf ',"evidence":"%s"' "$(json_escape "$evidence")"
        fi
        printf '}\n'
    } >> "$SENTINEL_FINDINGS_FILE"
}

# log_info / log_section — plain progress output (not findings)
log_info() {
    printf "${C_BLUE}[*]${C_RESET} %s\n" "$1" >&2
}

log_section() {
    printf "\n${C_BLUE}=== %s ===${C_RESET}\n" "$1" >&2
}

# reset_findings — clear the findings file (called once at the start of a scan)
reset_findings() {
    : > "$SENTINEL_FINDINGS_FILE"
}

# command_exists CMD — true if a command is available on this system
command_exists() {
    command -v "$1" >/dev/null 2>&1
}
