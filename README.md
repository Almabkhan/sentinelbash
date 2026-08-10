# SentinelBash — Linux Security & Incident Response Framework

A real, modular Bash-based Linux security audit framework — the same
category of tool as **Lynis** or **chkrootkit**, built from scratch to
demonstrate defensive security auditing, Bash scripting architecture, and
report generation.

This is a **defensive audit tool**: it reads local system state (users,
network config, running processes, logs, persistence mechanisms, SSH
configuration) and reports findings with a computed risk score. It does
not modify the system, exploit anything, or require destructive actions.

## What it actually checks

### System Reconnaissance
- OS/kernel version identification
- Disk usage, flagging filesystems above 75%/90% full

### User & Privilege Audit
- Non-root accounts with UID 0 (root-equivalent privilege)
- Accounts with empty passwords (`/etc/shadow`)
- `NOPASSWD` sudo rules in `/etc/sudoers` and `/etc/sudoers.d/`
- Count of accounts with interactive login shells

### Network Connection Analysis
- Listening TCP/UDP ports (via `ss` or `netstat`)
- Risky-by-default services (FTP, Telnet, MySQL, Redis, MongoDB,
  Elasticsearch, etc.) exposed on all interfaces vs. localhost-only
- Firewall status (`ufw`, `firewalld`, or `iptables`)

### Process & Service Audit
- Processes running from suspicious paths (`/tmp`, `/dev/shm`,
  `/var/tmp`) — a classic malware staging pattern
- Processes running from a **deleted binary** on disk — a real
  rootkit/persistence indicator
- High-CPU processes

### Authentication & Log Analysis
- Brute-force login pattern detection from `/var/log/auth.log` or
  `/var/log/secure` (failed-attempt counting per source IP)
- Sudo authentication failure counting

### Persistence Mechanism Audit
- System-wide and per-user cron jobs
- systemd services executing from suspicious locations
- SSH `authorized_keys` enumeration across all users
- Shell profile files (`.bashrc`, `.profile`, etc.) scanned for
  reverse-shell / download-and-execute patterns

### Security Hardening Checks
- SSH daemon config: `PermitRootLogin`, `PasswordAuthentication`,
  `PermitEmptyPasswords`, deprecated Protocol 1
- SUID/SGID binaries not on a known-standard baseline
- World-writable files in sensitive system directories

## Installation

```bash
git clone https://github.com/Almabkhan/sentinelbash
cd sentinelbash
chmod +x sentinel.sh
```

No external dependencies beyond standard Linux/GNU coreutils (`bash`,
`grep`, `awk`, `find`, `ps`) — this is intentional, so it runs on any
Linux box without a package-install step first.

## Usage

**Run all modules:**
```bash
./sentinel.sh
```

**Run specific modules only:**
```bash
./sentinel.sh --modules user,network,hardening
```

**Custom output directory:**
```bash
./sentinel.sh --output-dir /tmp/my_scan
```

**List available modules:**
```bash
./sentinel.sh --list-modules
```

Reports are saved as `{hostname}_report.json`, `{hostname}_report.csv`,
and `{hostname}_report.html` in the output directory.

## Example output

```text
======================================================================
  SentinelBash — Security Audit: myhost
======================================================================

=== System Reconnaissance ===
[*] OS: Ubuntu 24.04.4 LTS
[*] Kernel: 6.8.0-generic

=== User & Privilege Audit ===
[*] Checking for non-root accounts with UID 0...
[*] Checking for accounts with empty passwords...

=== Security Hardening Audit ===
[LOW] hardening  SUID binary not on the standard baseline: /usr/lib/dbus-1.0/dbus-daemon-launch-helper

======================================================================
  SCAN COMPLETE — Risk: Low (5/100)
  Total findings: 12
  Reports saved to: ./scan_output/
======================================================================
```

## Architecture

```text
sentinelbash/
├── sentinel.sh              # main orchestrator / CLI entry point
├── lib/
│   └── common.sh              # shared functions: finding emission, logging, colors
├── modules/
│   ├── system_audit.sh
│   ├── user_audit.sh
│   ├── network_audit.sh
│   ├── process_audit.sh
│   ├── log_analyzer.sh
│   ├── persistence_check.sh
│   └── hardening_check.sh
├── reports/
│   └── generate.sh            # risk scoring + JSON/CSV/HTML report generation
├── tests/
│   └── run_tests.sh           # dependency-free bash test suite (24 tests)
└── README.md
```

### Findings pipeline

Every module calls a single shared function, `emit_finding`, which:
1. Prints a color-coded line to the console immediately (so you see
   progress in real time)
2. Appends the same finding as one line of JSON to a shared findings
   file (JSON Lines format)

At the end of the scan, `reports/generate.sh` reads that findings file
once and renders it into JSON, CSV, and HTML — so every module only
needs to know how to *emit* a finding, not how to *format* one.

### Risk scoring

Each finding's severity (`critical`/`high`/`medium`/`low`/`info`) maps
to a numeric weight. The total weight is normalized against a "max
reasonable weight" constant to produce a 0–100 score, capped at 100 —
this avoids a system with many low-severity findings scoring worse
than one with a couple of criticals.

## Running the tests

```bash
./tests/run_tests.sh
```

24 tests cover `json_escape`, `emit_finding`'s JSON output, `command_exists`,
severity-weight mapping, risk-score computation (including the 100-cap and
empty-findings baseline), severity counting, and CSV/JSON report generation
— including a real JSON-validity check via `python3 -c "import json..."`.
No live system state is required, so the suite runs identically in any
environment, including CI.

## Known limitations

- **Local-only by design**: This audits the machine it runs on. For
  remote systems, run it directly on the target (e.g. via SSH) with
  proper authorization — it does not include remote-scanning
  capability.
- **Log format assumptions**: The brute-force detector expects the
  standard `sshd` log line format (`Failed password ... from <IP>`);
  heavily customized syslog formats may not match.
- **No baseline/allowlist file (yet)**: The SUID baseline and risky-port
  list are hardcoded constants rather than a configurable file — see
  Possible Extensions below.
- **Requires appropriate read permissions**: Several checks (empty
  passwords, full sudoers audit) require root to read `/etc/shadow`
  and produce complete results; run with `sudo` for a full audit.

## Possible extensions

- Move the SUID baseline and risky-port list into `config/` as
  editable YAML/JSON files instead of hardcoded constants
- Add a `--parallel` flag to run independent modules concurrently
- Add a rootkit-signature check (compare common binary hashes against
  known-good checksums)
- Add scheduled/cron-driven scanning with diff-against-last-run
  alerting
