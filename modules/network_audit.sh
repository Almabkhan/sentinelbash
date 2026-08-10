#!/usr/bin/env bash
###############################################################################
# modules/network_audit.sh — Network connection & firewall analysis
#
# Real checks on listening ports (via ss/netstat), risky-by-default services,
# and whether a firewall is active.
###############################################################################

# Ports that are commonly considered risky to expose without a specific reason
readonly RISKY_PORTS_LIST="21:FTP 23:Telnet 3306:MySQL 5432:PostgreSQL 6379:Redis 27017:MongoDB 9200:Elasticsearch"

run_network_audit() {
    log_section "Network Connection Analysis"

    local ss_cmd=""
    if command_exists ss; then
        ss_cmd="ss"
    elif command_exists netstat; then
        ss_cmd="netstat"
    else
        emit_finding "network" "info" "no_network_tool" \
            "Neither 'ss' nor 'netstat' is available — skipping listening port audit" ""
        return
    fi

    log_info "Enumerating listening TCP/UDP ports (using $ss_cmd)..."

    local listening_output
    if [[ "$ss_cmd" == "ss" ]]; then
        listening_output=$(ss -tulnp 2>/dev/null)
    else
        listening_output=$(netstat -tulnp 2>/dev/null)
    fi

    local port_count=0
    while IFS= read -r line; do
        # Extract the local address:port field (varies slightly by tool, so
        # we grep for a pattern that matches both ss and netstat output)
        local addr_port
        addr_port=$(echo "$line" | grep -oE '[0-9.\[\]:]+:[0-9]+[[:space:]]' | head -1 | tr -d '[:space:]')
        [[ -z "$addr_port" ]] && continue

        local port="${addr_port##*:}"
        [[ "$port" =~ ^[0-9]+$ ]] || continue

        port_count=$((port_count + 1))

        for entry in $RISKY_PORTS_LIST; do
            local risky_port="${entry%%:*}"
            local service_name="${entry##*:}"
            if [[ "$port" == "$risky_port" ]]; then
                local exposed_externally="no"
                if [[ "$addr_port" == 0.0.0.0:* || "$addr_port" == \[::\]:* || "$addr_port" == :::* ]]; then
                    exposed_externally="yes"
                fi

                if [[ "$exposed_externally" == "yes" ]]; then
                    emit_finding "network" "high" "risky_port_exposed" \
                        "Port $port ($service_name) is listening on all interfaces (0.0.0.0) — potentially exposed externally" "port=$port service=$service_name"
                else
                    emit_finding "network" "low" "risky_port_local" \
                        "Port $port ($service_name) is listening, but only on localhost" "port=$port service=$service_name"
                fi
            fi
        done
    done < <(echo "$listening_output" | grep -E 'LISTEN|udp')

    emit_finding "network" "info" "listening_ports_summary" \
        "$port_count listening port(s) found" ""

    log_info "Checking firewall status..."
    check_firewall_status
}

check_firewall_status() {
    local firewall_found="no"

    if command_exists ufw; then
        firewall_found="yes"
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1)
        if [[ "$ufw_status" == *"inactive"* ]]; then
            emit_finding "network" "medium" "firewall_inactive" "UFW is installed but inactive" ""
        else
            emit_finding "network" "info" "firewall_active" "UFW firewall is active" ""
        fi
    fi

    if command_exists firewall-cmd; then
        firewall_found="yes"
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            emit_finding "network" "info" "firewall_active" "firewalld is active" ""
        else
            emit_finding "network" "medium" "firewall_inactive" "firewalld is installed but not running" ""
        fi
    fi

    if command_exists iptables; then
        firewall_found="yes"
        local rule_count
        rule_count=$(iptables -L 2>/dev/null | grep -cE '^(ACCEPT|DROP|REJECT)')
        if [[ "$rule_count" -le 3 ]]; then
            emit_finding "network" "medium" "iptables_minimal_rules" \
                "iptables has only $rule_count rule(s) — firewall may not be meaningfully configured" ""
        fi
    fi

    if [[ "$firewall_found" == "no" ]]; then
        emit_finding "network" "high" "no_firewall_detected" \
            "No firewall tool (ufw, firewalld, iptables) detected on this system" ""
    fi
}
