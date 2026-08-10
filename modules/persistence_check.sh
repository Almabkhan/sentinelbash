#!/usr/bin/env bash
###############################################################################
# modules/persistence_check.sh — Suspicious persistence detection
#
# Real checks on the classic Linux persistence mechanisms attackers use to
# survive a reboot: cron jobs, systemd services, SSH authorized_keys, and
# shell profile files.
###############################################################################

run_persistence_check() {
    log_section "Persistence Mechanism Audit"

    log_info "Checking cron jobs..."
    check_cron_jobs

    log_info "Checking systemd services..."
    check_systemd_services

    log_info "Checking SSH authorized_keys..."
    check_ssh_keys

    log_info "Checking shell profile modifications..."
    check_shell_profiles
}

check_cron_jobs() {
    local found_any=0

    # System-wide crontab
    if [[ -r /etc/crontab ]]; then
        local entries
        entries=$(grep -cvE '^\s*(#|$)' /etc/crontab 2>/dev/null)
        if [[ "$entries" -gt 0 ]]; then
            found_any=1
            emit_finding "persistence" "info" "system_cron_entries" \
                "$entries active entries in /etc/crontab" "count=$entries"
        fi
    fi

    # /etc/cron.d/*
    if [[ -d /etc/cron.d ]]; then
        for f in /etc/cron.d/*; do
            [[ -f "$f" ]] || continue
            local entries
            entries=$(grep -cvE '^\s*(#|$)' "$f" 2>/dev/null)
            [[ "$entries" -gt 0 ]] && found_any=1
        done
    fi

    # Per-user crontabs
    if command_exists crontab && [[ -r /etc/passwd ]]; then
        while IFS=: read -r username _ uid _; do
            [[ "$uid" -lt 1000 && "$username" != "root" ]] && continue
            local user_cron
            user_cron=$(crontab -u "$username" -l 2>/dev/null | grep -vE '^\s*(#|$)')
            if [[ -n "$user_cron" ]]; then
                found_any=1
                emit_finding "persistence" "low" "user_cron_found" \
                    "User '$username' has active cron entries" "username=$username"
            fi
        done < /etc/passwd
    fi

    [[ "$found_any" -eq 0 ]] && emit_finding "persistence" "info" "no_cron_entries" "No active cron entries found" ""
}

check_systemd_services() {
    if ! command_exists systemctl; then
        return
    fi

    # Look for enabled services running from non-standard locations
    local unusual_count=0
    while IFS= read -r unit_file; do
        [[ -z "$unit_file" ]] && continue
        local exec_path
        exec_path=$(grep -oP '(?<=ExecStart=)\S+' "$unit_file" 2>/dev/null | head -1)
        [[ -z "$exec_path" ]] && continue

        for suspicious_dir in /tmp /dev/shm /var/tmp; do
            if [[ "$exec_path" == "$suspicious_dir"* ]]; then
                unusual_count=$((unusual_count + 1))
                emit_finding "persistence" "critical" "suspicious_systemd_service" \
                    "systemd unit $(basename "$unit_file") executes from $exec_path" "unit=$unit_file exec=$exec_path"
            fi
        done
    done < <(find /etc/systemd/system -name "*.service" 2>/dev/null)

    [[ "$unusual_count" -eq 0 ]] && emit_finding "persistence" "info" "systemd_clean" \
        "No systemd services executing from suspicious locations" ""
}

check_ssh_keys() {
    local total_keys=0

    while IFS= read -r authorized_keys_file; do
        [[ -r "$authorized_keys_file" ]] || continue
        local key_count
        key_count=$(grep -cE '^(ssh-|ecdsa-)' "$authorized_keys_file" 2>/dev/null || echo 0)
        total_keys=$((total_keys + key_count))

        if [[ "$key_count" -gt 5 ]]; then
            emit_finding "persistence" "medium" "many_ssh_keys" \
                "$authorized_keys_file contains $key_count authorized keys — worth reviewing for unauthorized entries" \
                "file=$authorized_keys_file count=$key_count"
        fi
    done < <(find /root /home -maxdepth 3 -name "authorized_keys" 2>/dev/null)

    emit_finding "persistence" "info" "ssh_keys_summary" "$total_keys total SSH authorized key(s) found across all users" ""
}

check_shell_profiles() {
    local -a suspicious_patterns=(
        'curl[^|]*\|[^|]*sh'
        'wget[^|]*\|[^|]*sh'
        'nc[[:space:]]+-e[[:space:]]+/bin/(sh|bash)'
        '/dev/tcp/'
        'base64[[:space:]]+-d[^|]*\|[^|]*sh'
    )

    for profile_glob in /root/.bashrc /root/.bash_profile /root/.profile /home/*/.bashrc /home/*/.bash_profile /home/*/.profile; do
        for profile_file in $profile_glob; do
            [[ -r "$profile_file" ]] || continue

            for pattern in "${suspicious_patterns[@]}"; do
                if grep -qE "$pattern" "$profile_file" 2>/dev/null; then
                    emit_finding "persistence" "critical" "suspicious_shell_profile" \
                        "Shell profile $profile_file contains a pattern consistent with a reverse-shell or download-and-execute payload" \
                        "file=$profile_file pattern=$pattern"
                    break
                fi
            done
        done
    done
}
