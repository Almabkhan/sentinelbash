#!/usr/bin/env bash
###############################################################################
# tests/run_tests.sh — SentinelBash test suite
#
# Simple, dependency-free bash test runner. Tests the shared library
# functions and report-generation logic against known inputs, without
# depending on live system state (so tests are reliable in any environment,
# including CI).
###############################################################################

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

source "$ROOT_DIR/lib/common.sh"
source "$ROOT_DIR/reports/generate.sh"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

assert_equals() {
    local expected="$1" actual="$2" test_name="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$expected" == "$actual" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo "  PASS: $test_name"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo "  FAIL: $test_name (expected '$expected', got '$actual')"
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" test_name="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$haystack" == *"$needle"* ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo "  PASS: $test_name"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo "  FAIL: $test_name (expected to find '$needle')"
    fi
}

echo "=== Testing lib/common.sh ==="

# --- json_escape tests ---
result=$(json_escape 'hello "world"')
assert_equals 'hello \"world\"' "$result" "json_escape handles double quotes"

result=$(json_escape 'back\slash')
assert_equals 'back\\slash' "$result" "json_escape handles backslashes"

# --- emit_finding tests ---
SENTINEL_FINDINGS_FILE="$(mktemp)"
export SENTINEL_FINDINGS_FILE
reset_findings

emit_finding "test_module" "high" "test_type" "Test description" "test evidence" 2>/dev/null
finding_line=$(cat "$SENTINEL_FINDINGS_FILE")

assert_contains "$finding_line" '"module":"test_module"' "emit_finding writes module field"
assert_contains "$finding_line" '"severity":"high"' "emit_finding writes severity field"
assert_contains "$finding_line" '"description":"Test description"' "emit_finding writes description field"
assert_contains "$finding_line" '"evidence":"test evidence"' "emit_finding writes evidence when provided"

reset_findings
emit_finding "test_module" "low" "test_type" "No evidence here" 2>/dev/null
finding_line=$(cat "$SENTINEL_FINDINGS_FILE")
if [[ "$finding_line" != *'"evidence"'* ]]; then
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "  PASS: emit_finding omits evidence field when not provided"
else
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1))
    echo "  FAIL: emit_finding omits evidence field when not provided"
fi

# --- command_exists tests ---
if command_exists bash; then
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "  PASS: command_exists finds a known command (bash)"
else
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1))
    echo "  FAIL: command_exists finds a known command (bash)"
fi

if ! command_exists this_command_should_never_exist_xyz123; then
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "  PASS: command_exists returns false for nonexistent command"
else
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1))
    echo "  FAIL: command_exists returns false for nonexistent command"
fi

echo ""
echo "=== Testing reports/generate.sh ==="

# --- severity_weight tests ---
assert_equals "10" "$(severity_weight critical)" "severity_weight: critical = 10"
assert_equals "7" "$(severity_weight high)" "severity_weight: high = 7"
assert_equals "4" "$(severity_weight medium)" "severity_weight: medium = 4"
assert_equals "2" "$(severity_weight low)" "severity_weight: low = 2"
assert_equals "0" "$(severity_weight info)" "severity_weight: info = 0"
assert_equals "0" "$(severity_weight unknown_severity)" "severity_weight: unknown defaults to 0"

# --- compute_risk_score tests ---
test_findings_file="$(mktemp)"

# Empty findings -> score 0, Low
: > "$test_findings_file"
result=$(compute_risk_score "$test_findings_file")
assert_equals "0|Low" "$result" "compute_risk_score: no findings = 0|Low"

# A few critical findings -> high score
{
  echo '{"module":"x","severity":"critical","type":"y","description":"z"}'
  echo '{"module":"x","severity":"critical","type":"y","description":"z"}'
  echo '{"module":"x","severity":"critical","type":"y","description":"z"}'
} > "$test_findings_file"
result=$(compute_risk_score "$test_findings_file")
score="${result%%|*}"
if [[ "$score" -ge 30 ]]; then
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "  PASS: compute_risk_score: 3 criticals produce a meaningfully high score ($score)"
else
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1))
    echo "  FAIL: compute_risk_score: 3 criticals produced too low a score ($score)"
fi

# Score should never exceed 100
{
  for _ in $(seq 1 20); do
    echo '{"module":"x","severity":"critical","type":"y","description":"z"}'
  done
} > "$test_findings_file"
result=$(compute_risk_score "$test_findings_file")
score="${result%%|*}"
if [[ "$score" -le 100 ]]; then
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "  PASS: compute_risk_score: score is capped at 100"
else
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1))
    echo "  FAIL: compute_risk_score: score exceeded 100 ($score)"
fi

# --- count_by_severity tests ---
{
  echo '{"module":"x","severity":"high","type":"y","description":"z"}'
  echo '{"module":"x","severity":"high","type":"y","description":"z"}'
  echo '{"module":"x","severity":"low","type":"y","description":"z"}'
} > "$test_findings_file"
assert_equals "2" "$(count_by_severity "$test_findings_file" high)" "count_by_severity counts high findings correctly"
assert_equals "1" "$(count_by_severity "$test_findings_file" low)" "count_by_severity counts low findings correctly"
assert_equals "0" "$(count_by_severity "$test_findings_file" critical)" "count_by_severity returns 0 for absent severity"

# --- generate_csv_report tests ---
csv_output="$(mktemp)"
{
  echo '{"module":"user","severity":"critical","type":"empty_password","description":"Test finding, with comma"}'
} > "$test_findings_file"
generate_csv_report "$test_findings_file" "$csv_output"
csv_content=$(cat "$csv_output")
assert_contains "$csv_content" "module,severity,type,description" "generate_csv_report writes header row"
assert_contains "$csv_content" "user,critical,empty_password" "generate_csv_report writes finding data"

# --- generate_json_report tests ---
json_output="$(mktemp)"
generate_json_report "$test_findings_file" "$json_output" "test-host" "2026-01-01T00:00:00Z"

# Structural sanity check done in pure bash (portable across platforms —
# avoids relying on a working `python3`/`python` in PATH, which can be an
# unreliable App Execution Alias stub on some Windows setups rather than
# a real interpreter).
json_content=$(cat "$json_output")
json_valid=1
[[ "$json_content" == \{* ]] || json_valid=0
[[ "$json_content" == *\} ]] || json_valid=0
[[ "$json_content" == *'"target": "test-host"'* ]] || json_valid=0
[[ "$json_content" == *'"findings"'* ]] || json_valid=0
# Braces/brackets should balance
open_braces=$(grep -o '{' <<< "$json_content" | wc -l)
close_braces=$(grep -o '}' <<< "$json_content" | wc -l)
[[ "$open_braces" == "$close_braces" ]] || json_valid=0

if [[ "$json_valid" -eq 1 ]]; then
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "  PASS: generate_json_report produces structurally valid JSON"
else
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1))
    echo "  FAIL: generate_json_report produced structurally invalid JSON"
fi

# Bonus check: if a real python3/python is available, also do a full parse
# (informational — does not affect pass/fail, since a broken Windows Store
# alias stub shouldn't fail an otherwise-correct test run)
for py_cmd in python3 python; do
    if command_exists "$py_cmd"; then
        if "$py_cmd" -c "import json,sys; json.load(sys.stdin)" < "$json_output" >/dev/null 2>&1; then
            echo "  INFO: full JSON parse via '$py_cmd' also succeeded"
        fi
        break
    fi
done

# Cleanup
rm -f "$test_findings_file" "$csv_output" "$json_output" "$SENTINEL_FINDINGS_FILE"

echo ""
echo "======================================================================"
echo "  Tests run: $TESTS_RUN  |  Passed: $TESTS_PASSED  |  Failed: $TESTS_FAILED"
echo "======================================================================"

if [[ "$TESTS_FAILED" -gt 0 ]]; then
    exit 1
fi
exit 0
