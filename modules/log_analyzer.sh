#!/usr/bin/env bash
###############################################################################
# modules/log_analyzer.sh — Authentication & system log analysis
#
# Real log parsing (auth.log / secure) for brute-force attempts and
# suspicious sudo usage — the Bash-native counterpart to the Python
# log-analyzer project, but reading live system logs directly.
###############################################################################

readonly BRUTE_FORCE_THRESHOLD=5

run_log_analysis() {
    log_section "Authentication & Log Analysis"

    local auth_log=""
    for candidate in /var/log/auth.log /var/log/secure; do
        if [[ -r "$candidate" ]]; then
            auth_log="$candidate"
            break
        fi
    done

    if [[ -z "$auth_log" ]]; then
        emit_finding "log_analyzer" "info" "no_auth_log" \
            "No readable auth log found (/var/log/auth.log or /var/log/secure) — skipping log analysis" ""
        return
    fi

    log_info "Analyzing $auth_log for brute-force patterns..."
    check_brute_force "$auth_log"

    log_info "Analyzing sudo usage..."
    check_sudo_usage "$auth_log"
}

check_brute_force() {
    local log_file="$1"

    # Count failed password attempts per source IP.
    # NOTE: must initialize with '=()' explicitly — 'declare -A arr' alone
    # leaves it in a state where, under 'set -u', even checking its length
    # (${#arr[@]}) throws "unbound variable" if no keys are ever added.
    declare -A ip_fail_counts=()

    while IFS= read -r line; do
        local ip
        ip=$(echo "$line" | grep -oE 'from [0-9]{1,3}(\.[0-9]{1,3}){3}' | awk '{print $2}')
        [[ -z "$ip" ]] && continue
        ip_fail_counts["$ip"]=$(( ${ip_fail_counts["$ip"]:-0} + 1 ))
    done < <(grep -i "failed password" "$log_file" 2>/dev/null)

    if [[ ${#ip_fail_counts[@]} -gt 0 ]]; then
        for ip in "${!ip_fail_counts[@]}"; do
            local count="${ip_fail_counts[$ip]}"
            if [[ "$count" -ge "$BRUTE_FORCE_THRESHOLD" ]]; then
                local severity="medium"
                [[ "$count" -ge $((BRUTE_FORCE_THRESHOLD * 2)) ]] && severity="high"

                emit_finding "log_analyzer" "$severity" "brute_force_detected" \
                    "$count failed login attempts from $ip" "ip=$ip attempts=$count"
            fi
        done
    fi

    if [[ ${#ip_fail_counts[@]} -eq 0 ]]; then
        emit_finding "log_analyzer" "info" "no_brute_force" "No failed login patterns found in $log_file" ""
    fi
}

check_sudo_usage() {
    local log_file="$1"
    local sudo_failures
    sudo_failures=$(grep -c "sudo.*authentication failure" "$log_file" 2>/dev/null)
    sudo_failures="${sudo_failures:-0}"

    if [[ "$sudo_failures" -gt 0 ]]; then
        emit_finding "log_analyzer" "medium" "sudo_auth_failures" \
            "$sudo_failures sudo authentication failure(s) found in log" "count=$sudo_failures"
    fi
}
