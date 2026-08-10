#!/usr/bin/env bash
###############################################################################
# reports/generate.sh — Risk scoring and report generation
#
# Reads the findings JSON-lines file and produces a consolidated JSON
# report, a CSV export, and a styled HTML report with a computed risk score.
###############################################################################

# severity_weight SEVERITY — echo the numeric weight for a severity level
severity_weight() {
    case "$1" in
        critical) echo 10 ;;
        high) echo 7 ;;
        medium) echo 4 ;;
        low) echo 2 ;;
        *) echo 0 ;;
    esac
}

# compute_risk_score FINDINGS_FILE — prints "SCORE|LEVEL" to stdout
compute_risk_score() {
    local findings_file="$1"
    local total_weight=0

    while IFS= read -r severity; do
        [[ -z "$severity" ]] && continue
        local w
        w=$(severity_weight "$severity")
        total_weight=$((total_weight + w))
    done < <(grep -oE '"severity":"[a-z]+"' "$findings_file" 2>/dev/null | sed 's/"severity":"//;s/"//')

    local max_reasonable_weight=80
    local score=$(( total_weight * 100 / max_reasonable_weight ))
    [[ "$score" -gt 100 ]] && score=100

    local level="Low"
    [[ "$score" -ge 15 ]] && level="Medium"
    [[ "$score" -ge 40 ]] && level="High"
    [[ "$score" -ge 70 ]] && level="Critical"

    echo "${score}|${level}"
}

# count_by_severity FINDINGS_FILE SEVERITY — count findings of a given severity
count_by_severity() {
    local count
    count=$(grep -c "\"severity\":\"$2\"" "$1" 2>/dev/null)
    echo "${count:-0}"
}

generate_json_report() {
    local findings_file="$1" output_file="$2" target="$3" timestamp="$4"

    {
        echo "{"
        echo "  \"target\": \"$target\","
        echo "  \"scan_timestamp\": \"$timestamp\","
        echo "  \"findings\": ["
        local first=1
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if [[ "$first" -eq 0 ]]; then echo ","; fi
            printf "    %s" "$line"
            first=0
        done < "$findings_file"
        echo ""
        echo "  ]"
        echo "}"
    } > "$output_file"
}

generate_csv_report() {
    local findings_file="$1" output_file="$2"

    echo "module,severity,type,description" > "$output_file"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local module severity type description
        module=$(echo "$line" | grep -oE '"module":"[^"]*"' | sed 's/"module":"//;s/"$//')
        severity=$(echo "$line" | grep -oE '"severity":"[^"]*"' | sed 's/"severity":"//;s/"$//')
        type=$(echo "$line" | grep -oE '"type":"[^"]*"' | sed 's/"type":"//;s/"$//')
        description=$(echo "$line" | grep -oE '"description":"[^"]*"' | sed 's/"description":"//;s/"$//')
        # Escape any commas in description for valid CSV
        description="${description//,/;}"
        echo "$module,$severity,$type,$description" >> "$output_file"
    done < "$findings_file"
}

generate_html_report() {
    local findings_file="$1" output_file="$2" target="$3" timestamp="$4"

    local score_and_level
    score_and_level=$(compute_risk_score "$findings_file")
    local score="${score_and_level%%|*}"
    local level="${score_and_level##*|}"

    local critical_count high_count medium_count low_count
    critical_count=$(count_by_severity "$findings_file" "critical")
    high_count=$(count_by_severity "$findings_file" "high")
    medium_count=$(count_by_severity "$findings_file" "medium")
    low_count=$(count_by_severity "$findings_file" "low")

    cat > "$output_file" << HTML_HEADER
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SentinelBash Report: $target</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: #0d1117; color: #c9d1d9; max-width: 900px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }
  .risk-badge { display: inline-block; padding: 6px 16px; border-radius: 6px; font-weight: bold; }
  .risk-Critical { background: #f85149; color: white; }
  .risk-High { background: #db6d28; color: white; }
  .risk-Medium { background: #d29922; color: black; }
  .risk-Low { background: #3fb950; color: black; }
  table { border-collapse: collapse; width: 100%; margin: 15px 0; }
  th, td { border: 1px solid #30363d; padding: 8px 12px; text-align: left; }
  th { background: #161b22; }
  .finding { background: #161b22; border-left: 4px solid #30363d; padding: 12px 16px; margin: 12px 0; border-radius: 4px; }
  .sev-critical { border-left-color: #f85149; }
  .sev-high { border-left-color: #db6d28; }
  .sev-medium { border-left-color: #d29922; }
  .sev-low { border-left-color: #3fb950; }
  .sev-info { border-left-color: #58a6ff; }
  .meta { color: #8b949e; font-size: 0.9em; }
</style>
</head>
<body>
  <h1>SentinelBash Security Report</h1>
  <p class="meta">Target: <strong>$target</strong> | Scanned: $timestamp</p>
  <h2>Risk Assessment</h2>
  <span class="risk-badge risk-$level">$level — $score/100</span>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    <tr><td>Critical</td><td>$critical_count</td></tr>
    <tr><td>High</td><td>$high_count</td></tr>
    <tr><td>Medium</td><td>$medium_count</td></tr>
    <tr><td>Low</td><td>$low_count</td></tr>
  </table>
  <h2>Findings</h2>
HTML_HEADER

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local module severity type description
        module=$(echo "$line" | grep -oE '"module":"[^"]*"' | sed 's/"module":"//;s/"$//')
        severity=$(echo "$line" | grep -oE '"severity":"[^"]*"' | sed 's/"severity":"//;s/"$//')
        type=$(echo "$line" | grep -oE '"type":"[^"]*"' | sed 's/"type":"//;s/"$//')
        description=$(echo "$line" | grep -oE '"description":"[^"]*"' | sed 's/"description":"//;s/"$//')

        echo "  <div class=\"finding sev-$severity\"><strong>[$severity] $module :: $type</strong><br>$description</div>" >> "$output_file"
    done < "$findings_file"

    echo "</body></html>" >> "$output_file"
}
