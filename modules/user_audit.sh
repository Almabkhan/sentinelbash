#!/usr/bin/env bash
###############################################################################
# modules/user_audit.sh — User & privilege auditing
#
# Real checks against /etc/passwd, /etc/shadow, and sudoers configuration —
# the same categories of checks tools like Lynis and CIS benchmarks perform.
###############################################################################

run_user_audit() {
    log_section "User & Privilege Audit"

    if [[ ! -r /etc/passwd ]]; then
        emit_finding "user" "info" "passwd_unreadable" "/etc/passwd not readable, skipping user audit" ""
        return
    fi

    log_info "Checking for non-root accounts with UID 0..."
    while IFS=: read -r username _ uid _; do
        if [[ "$uid" == "0" && "$username" != "root" ]]; then
            emit_finding "user" "critical" "uid_zero_account" \
                "Non-root account '$username' has UID 0 (root-equivalent privileges)" "username=$username"
        fi
    done < /etc/passwd

    log_info "Checking for accounts with empty passwords..."
    if [[ -r /etc/shadow ]]; then
        while IFS=: read -r username password _; do
            if [[ -z "$password" ]]; then
                emit_finding "user" "critical" "empty_password" \
                    "Account '$username' has no password set" "username=$username"
            fi
        done < /etc/shadow
    else
        emit_finding "user" "info" "shadow_unreadable" \
            "/etc/shadow not readable (requires root) — skipping empty-password check" ""
    fi

    log_info "Checking users with valid login shells..."
    local login_shell_count=0
    while IFS=: read -r username _ _ _ _ _ shell; do
        case "$shell" in
            */bash|*/sh|*/zsh|*/fish|*/csh|*/ksh|*/dash)
                login_shell_count=$((login_shell_count + 1))
                ;;
        esac
    done < /etc/passwd
    emit_finding "user" "info" "login_capable_accounts" \
        "$login_shell_count account(s) have an interactive login shell" ""

    log_info "Checking sudoers configuration..."
    if [[ -r /etc/sudoers ]]; then
        if grep -qE '^\s*[^#].*NOPASSWD' /etc/sudoers 2>/dev/null; then
            emit_finding "user" "medium" "nopasswd_sudo" \
                "NOPASSWD sudo rule(s) found in /etc/sudoers — allows privilege escalation without a password prompt" ""
        fi
    fi

    if [[ -d /etc/sudoers.d ]]; then
        for f in /etc/sudoers.d/*; do
            [[ -f "$f" ]] || continue
            if grep -qE '^\s*[^#].*NOPASSWD' "$f" 2>/dev/null; then
                emit_finding "user" "medium" "nopasswd_sudo" \
                    "NOPASSWD sudo rule found in $f" "file=$f"
            fi
        done
    fi
}
