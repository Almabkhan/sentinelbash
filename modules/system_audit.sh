#!/usr/bin/env bash
###############################################################################
# modules/system_audit.sh — Basic system reconnaissance
#
# Collects OS/kernel version, uptime, disk usage, and flags disks that are
# critically low on free space (a real operational/security concern — a
# full disk can silently break logging, which itself is a security risk).
###############################################################################

run_system_audit() {
    log_section "System Reconnaissance"

    local os_info kernel_version uptime_info

    if [[ -f /etc/os-release ]]; then
        os_info=$(grep -E '^PRETTY_NAME=' /etc/os-release | cut -d'"' -f2)
    else
        os_info="unknown"
    fi
    log_info "OS: $os_info"
    emit_finding "system" "info" "os_identified" "Operating system: $os_info" ""

    kernel_version=$(uname -r)
    log_info "Kernel: $kernel_version"
    emit_finding "system" "info" "kernel_version" "Kernel version: $kernel_version" ""

    if command_exists uptime; then
        uptime_info=$(uptime -p 2>/dev/null || uptime)
        log_info "Uptime: $uptime_info"
    fi

    # Disk usage — flag any filesystem above 90% used
    if command_exists df; then
        log_info "Checking disk usage..."
        while IFS= read -r usage_pct mount_point; do
            [[ "$usage_pct" =~ ^[0-9]+$ ]] || continue

            if [[ "$usage_pct" -ge 90 ]]; then
                emit_finding "system" "high" "disk_space_critical" \
                    "Filesystem $mount_point is ${usage_pct}% full" ""
            elif [[ "$usage_pct" -ge 75 ]]; then
                emit_finding "system" "medium" "disk_space_warning" \
                    "Filesystem $mount_point is ${usage_pct}% full" ""
            fi
        done < <(df -P 2>/dev/null | tail -n +2 | awk '{gsub(/%/,"",$5); print $5, $6}')
    fi
}
