#!/usr/bin/env bash
###############################################################################
# sentinel.sh — SentinelBash: Linux Security & Incident Response Framework
#
# Runs a set of real, defensive security audit modules against the local
# system (user accounts, network exposure, running processes, auth logs,
# persistence mechanisms, and SSH/hardening configuration) and produces
# JSON, CSV, and HTML reports with a computed risk score.
#
# This is a defensive AUDIT tool — it reads system state and reports on
# it. It does not modify anything, exploit anything, or require any
# destructive action to run.
#
# Usage:
#   ./sentinel.sh                          Run all modules
#   ./sentinel.sh --modules user,network    Run only specific modules
#   ./sentinel.sh --output-dir ./myreports  Custom report output directory
#   ./sentinel.sh --list-modules            List available modules
###############################################################################

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly AVAILABLE_MODULES="system user network process log persistence hardening"

usage() {
    cat << EOF
SentinelBash — Linux Security & Incident Response Framework

Usage: $0 [OPTIONS]

Options:
  --modules LIST      Comma-separated list of modules to run (default: all)
                       Available: $AVAILABLE_MODULES
  --output-dir DIR     Directory to save reports (default: ./scan_output)
  --list-modules       List available modules and exit
  --help               Show this help message

Examples:
  $0
  $0 --modules user,network,hardening
  $0 --output-dir /tmp/my_scan
EOF
}

list_modules() {
    cat << EOF
Available modules:
  system        System reconnaissance (OS, kernel, disk usage)
  user          User & privilege auditing (UID 0, empty passwords, sudoers)
  network       Network connection analysis (listening ports, firewall)
  process       Process/service audit (suspicious paths, deleted binaries)
  log           Authentication & log analysis (brute force, sudo abuse)
  persistence   Persistence mechanism detection (cron, systemd, SSH keys)
  hardening     Security hardening checks (SSH config, SUID, world-writable)
EOF
}

main() {
    local selected_modules="$AVAILABLE_MODULES"
    local output_dir="./scan_output"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --modules)
                selected_modules="${2//,/ }"
                shift 2
                ;;
            --output-dir)
                output_dir="$2"
                shift 2
                ;;
            --list-modules)
                list_modules
                exit 0
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                usage
                exit 1
                ;;
        esac
    done

    mkdir -p "$output_dir"
    SENTINEL_FINDINGS_FILE="$(mktemp)"
    export SENTINEL_FINDINGS_FILE
    reset_findings

    local target
    target="$(hostname 2>/dev/null || echo "unknown-host")"
    local timestamp
    timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    echo "======================================================================"
    echo "  SentinelBash — Security Audit: $target"
    echo "======================================================================"
    echo ""
    echo "NOTE: This tool audits the LOCAL system it runs on. For remote"
    echo "systems, run it directly on the target (e.g. via SSH) with proper"
    echo "authorization."
    echo ""

    for module in $selected_modules; do
        case "$module" in
            system)
                source "$SCRIPT_DIR/modules/system_audit.sh"
                run_system_audit
                ;;
            user)
                source "$SCRIPT_DIR/modules/user_audit.sh"
                run_user_audit
                ;;
            network)
                source "$SCRIPT_DIR/modules/network_audit.sh"
                run_network_audit
                ;;
            process)
                source "$SCRIPT_DIR/modules/process_audit.sh"
                run_process_audit
                ;;
            log)
                source "$SCRIPT_DIR/modules/log_analyzer.sh"
                run_log_analysis
                ;;
            persistence)
                source "$SCRIPT_DIR/modules/persistence_check.sh"
                run_persistence_check
                ;;
            hardening)
                source "$SCRIPT_DIR/modules/hardening_check.sh"
                run_hardening_check
                ;;
            *)
                echo "Unknown module: $module (skipping)" >&2
                ;;
        esac
    done

    # shellcheck source=reports/generate.sh
    source "$SCRIPT_DIR/reports/generate.sh"

    local json_path="$output_dir/${target}_report.json"
    local csv_path="$output_dir/${target}_report.csv"
    local html_path="$output_dir/${target}_report.html"

    generate_json_report "$SENTINEL_FINDINGS_FILE" "$json_path" "$target" "$timestamp"
    generate_csv_report "$SENTINEL_FINDINGS_FILE" "$csv_path"
    generate_html_report "$SENTINEL_FINDINGS_FILE" "$html_path" "$target" "$timestamp"

    local score_and_level
    score_and_level=$(compute_risk_score "$SENTINEL_FINDINGS_FILE")
    local score="${score_and_level%%|*}"
    local level="${score_and_level##*|}"
    local total_findings
    total_findings=$(wc -l < "$SENTINEL_FINDINGS_FILE" | tr -d ' ')

    echo ""
    echo "======================================================================"
    echo "  SCAN COMPLETE — Risk: $level ($score/100)"
    echo "  Total findings: $total_findings"
    echo "  Reports saved to: $output_dir/"
    echo "======================================================================"

    rm -f "$SENTINEL_FINDINGS_FILE"
}

main "$@"
