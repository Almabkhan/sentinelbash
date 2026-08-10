#!/usr/bin/env bash
###############################################################################
# modules/process_audit.sh — Suspicious process/service detection
#
# Real process-table analysis: processes running from unusual locations
# (e.g. /tmp, /dev/shm — classic malware staging areas), processes whose
# binary has been deleted from disk (a real rootkit/persistence indicator),
# and high resource consumers.
###############################################################################

readonly SUSPICIOUS_PROCESS_PATHS="/tmp /dev/shm /var/tmp"

run_process_audit() {
    log_section "Process & Service Audit"

    if ! command_exists ps; then
        emit_finding "process" "info" "no_ps_tool" "'ps' command not available — skipping process audit" ""
        return
    fi

    log_info "Checking for processes running from suspicious paths..."
    check_suspicious_process_paths

    log_info "Checking for processes with deleted binaries..."
    check_deleted_binaries

    log_info "Checking for high resource consumers..."
    check_high_resource_processes
}

check_suspicious_process_paths() {
    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue
        local exe_path
        exe_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
        [[ -z "$exe_path" ]] && continue

        for suspicious_dir in $SUSPICIOUS_PROCESS_PATHS; do
            if [[ "$exe_path" == "$suspicious_dir"/* ]]; then
                local cmdline
                cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
                emit_finding "process" "critical" "process_from_suspicious_path" \
                    "Process PID $pid is running from $exe_path — a common malware staging location" \
                    "pid=$pid path=$exe_path cmdline=$cmdline"
            fi
        done
    done < <(find /proc -maxdepth 1 -regex '/proc/[0-9]+' -printf '%f\n' 2>/dev/null)
}

check_deleted_binaries() {
    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue
        local exe_link
        exe_link=$(readlink "/proc/$pid/exe" 2>/dev/null)

        if [[ "$exe_link" == *"(deleted)"* ]]; then
            local cmdline
            cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
            emit_finding "process" "high" "deleted_binary_running" \
                "Process PID $pid is running from a deleted binary — possible rootkit or post-exploitation persistence" \
                "pid=$pid exe=$exe_link cmdline=$cmdline"
        fi
    done < <(find /proc -maxdepth 1 -regex '/proc/[0-9]+' -printf '%f\n' 2>/dev/null)
}

check_high_resource_processes() {
    # Top CPU consumers — exclude 'ps' itself, since a freshly-spawned ps
    # process commonly shows an inflated %CPU reading for itself (a known
    # quirk of how %CPU is computed for very short-lived processes).
    local top_cpu
    top_cpu=$(ps -eo pid,comm,%cpu --sort=-%cpu --no-headers 2>/dev/null | awk '$2 != "ps"' | head -3)

    if [[ -n "$top_cpu" ]]; then
        while IFS= read -r line; do
            local cpu_pct
            cpu_pct=$(echo "$line" | awk '{print $3}')
            if [[ "$cpu_pct" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
                local cpu_int="${cpu_pct%.*}"
                if [[ "$cpu_int" -ge 80 ]]; then
                    emit_finding "process" "medium" "high_cpu_process" \
                        "Process consuming ${cpu_pct}% CPU: $(echo "$line" | awk '{print $2}')" "$line"
                fi
            fi
        done <<< "$top_cpu"
    fi
}
