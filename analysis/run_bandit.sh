#!/usr/bin/env bash
# Runs Bandit static analysis on every generated code sample and writes
# JSON reports to the matching subfolder in analysis/bandit_reports/.
#
# Usage (from repo root):
#   chmod +x analysis/run_bandit.sh
#   ./analysis/run_bandit.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATED_DIR="${REPO_ROOT}/generated_code"
REPORTS_DIR="${REPO_ROOT}/analysis/bandit_reports"

LLMS=("chatgpt" "gemini" "claude_code")
STYLES=("naive" "secure")
TASKS=(
  "task1_registration"
  "task2_password_storage"
  "task3_login_endpoint"
  "task4_session_management"
  "task5_password_reset"
)

echo "=== Bandit Analysis Run: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ==="
echo "Repo root : ${REPO_ROOT}"
echo ""

total=0
skipped=0
failed=0

for llm in "${LLMS[@]}"; do
  for style in "${STYLES[@]}"; do

    # Map (llm, style) to the bandit_reports subdirectory name
    if [[ "${style}" == "naive" ]]; then
      report_subdir="${llm}_naive"
    else
      report_subdir="${llm}_secure"
    fi

    src_dir="${GENERATED_DIR}/${llm}/${style}"
    out_dir="${REPORTS_DIR}/${report_subdir}"

    mkdir -p "${out_dir}"

    for task in "${TASKS[@]}"; do
      src_file="${src_dir}/${task}.py"
      out_file="${out_dir}/${task}.json"

      if [[ ! -f "${src_file}" ]]; then
        echo "[SKIP]  ${src_file} not found"
        ((skipped++)) || true
        continue
      fi

      echo "[RUN]   bandit -> ${src_file}"
      if bandit \
          --format json \
          --output "${out_file}" \
          --severity-level low \
          --confidence-level low \
          "${src_file}" 2>/dev/null; then
        echo "[OK]    Report: ${out_file}"
      else
        # Bandit exits non-zero when it finds issues; that is expected.
        # Only treat it as a true failure if the output file was not created.
        if [[ -f "${out_file}" ]]; then
          echo "[WARN]  Issues found (see ${out_file})"
        else
          echo "[FAIL]  bandit produced no output for ${src_file}"
          ((failed++)) || true
        fi
      fi

      ((total++)) || true
    done
  done
done

echo ""
echo "=== Done ==="
echo "Processed : ${total}"
echo "Skipped   : ${skipped}"
echo "Failed    : ${failed}"
