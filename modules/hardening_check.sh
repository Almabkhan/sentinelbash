#!/usr/bin/env bash
###############################################################################
# modules/hardening_check.sh — Security-hardening checks
#
# Real checks against SSH daemon configuration, SUID/SGID binaries, and
# world-writable files — standard CIS-benchmark-style hardening checks.
###############################################################################

run_hardening_check() {
    log_section "Security Hardening Audit"

    log_info "Checking SSH daemon configuration..."
    check_ssh_config

    log_info "Checking for unusual SUID/SGID binaries..."
    check_suid_binaries

    log_info "Checking for world-writable files in sensitive locations..."
    check_world_writable_files
}

# Known-standard SUID binaries — flagging every SUID binary on a system
# produces mostly noise, since dozens are standard (passwd, sudo, ping,
# mount, etc.). We only flag SUID binaries NOT on this baseline list,
# since those are the ones worth a human looking at.
readonly KNOWN_SUID_BASELINE="/usr/bin/passwd /usr/bin/sudo /usr/bin/su /usr/bin/mount /usr/bin/umount /usr/bin/ping /usr/bin/ping6 /usr/bin/chsh /usr/bin/chfn /usr/bin/gpasswd /usr/bin/newgrp /usr/bin/pkexec /usr/bin/crontab /usr/lib/openssh/ssh-keysign /usr/bin/fusermount /usr/bin/fusermount3 /usr/bin/mount.nfs"

check_ssh_config() {
    local sshd_config="/etc/ssh/sshd_config"
    [[ -r "$sshd_config" ]] || { emit_finding "hardening" "info" "no_sshd_config" "sshd_config not found or not readable"; return; }

    local permit_root_login
    permit_root_login=$(grep -iE '^\s*PermitRootLogin' "$sshd_config" | awk '{print $2}' | tail -1)
    if [[ "$permit_root_login" == "yes" ]]; then
        emit_finding "hardening" "high" "ssh_root_login_enabled" \
            "SSH PermitRootLogin is set to 'yes' — root can log in directly over SSH" ""
    fi

    local password_auth
    password_auth=$(grep -iE '^\s*PasswordAuthentication' "$sshd_config" | awk '{print $2}' | tail -1)
    if [[ "$password_auth" == "yes" ]]; then
        emit_finding "hardening" "medium" "ssh_password_auth_enabled" \
            "SSH PasswordAuthentication is enabled — key-based auth only is more resistant to brute force" ""
    fi

    local protocol
    protocol=$(grep -iE '^\s*Protocol' "$sshd_config" | awk '{print $2}' | tail -1)
    if [[ "$protocol" == "1" ]]; then
        emit_finding "hardening" "critical" "ssh_protocol_v1" \
            "SSH is configured to allow Protocol 1, which is cryptographically broken" ""
    fi

    local permit_empty
    permit_empty=$(grep -iE '^\s*PermitEmptyPasswords' "$sshd_config" | awk '{print $2}' | tail -1)
    if [[ "$permit_empty" == "yes" ]]; then
        emit_finding "hardening" "critical" "ssh_empty_passwords_allowed" \
            "SSH PermitEmptyPasswords is enabled" ""
    fi
}

check_suid_binaries() {
    local unusual_count=0

    while IFS= read -r suid_file; do
        [[ -z "$suid_file" ]] && continue

        local is_known=0
        for known in $KNOWN_SUID_BASELINE; do
            [[ "$suid_file" == "$known" ]] && is_known=1 && break
        done

        if [[ "$is_known" -eq 0 ]]; then
            unusual_count=$((unusual_count + 1))
            emit_finding "hardening" "low" "unusual_suid_binary" \
                "SUID binary not on the standard baseline: $suid_file" "path=$suid_file"
        fi
    done < <(find / -xdev -perm -4000 -type f 2>/dev/null)

    emit_finding "hardening" "info" "suid_scan_summary" \
        "$unusual_count SUID binary/binaries found outside the standard baseline" ""
}

check_world_writable_files() {
    local sensitive_dirs="/etc /usr/bin /usr/sbin /bin /sbin"
    local count=0

    for dir in $sensitive_dirs; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r wfile; do
            count=$((count + 1))
            emit_finding "hardening" "medium" "world_writable_file" \
                "World-writable file in a sensitive directory: $wfile" "path=$wfile"
        done < <(find "$dir" -xdev -type f -perm -0002 2>/dev/null | head -20)
    done

    [[ "$count" -eq 0 ]] && emit_finding "hardening" "info" "no_world_writable" \
        "No world-writable files found in sensitive directories" ""
}
