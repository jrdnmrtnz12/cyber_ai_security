# AI-Generated Code Security Comparison

## What This Project Is About

I wanted to find out whether AI tools actually write secure code — and more importantly, whether
asking them to write secure code makes any difference. I picked three LLMs (ChatGPT, Gemini, and
Claude Code) and gave each one the same five authentication tasks twice: once with a plain prompt
that just described the task, and once with a prompt that explicitly asked for secure practices
like bcrypt, parameterized queries, and HTTPS-only cookies. That gave me 30 code samples total.
I then ran each one through Bandit (a static analysis tool) and did a manual review against the
OWASP Top 10 to see what vulnerabilities ended up in the code and whether the security aware
prompt actually helped.

---

## Folder Breakdown

### `prompts/`
The exact text I sent to each LLM. There are two files per task one for the naive prompt and
one for the security aware prompt. These are plain `.txt` files so the wording is fully
reproducible.

### `generated_code/`
The raw code each LLM returned, organized by model and prompt style. Each subfolder
(`chatgpt/naive/`, `gemini/secure/`, etc.) contains five Python files, one per task. The files
are unedited, exactly what the model produced, with a docstring at the top recording the LLM,
prompt style, date, and any observations about how the model responded.

### `analysis/`
Everything related to evaluating the code.

- **`bandit_reports/`** — JSON output from Bandit for each of the 30 samples, organized into
  subfolders matching the `generated_code/` structure. Run `run_bandit.sh` to regenerate these.

- **`manual_review/`** — One Markdown file per sample (e.g., `chatgpt_naive_task3_login_endpoint.md`)
  where I worked through the security checklist. `review_template.md` is the blank template I
  copied for each one.

- **`run_bandit.sh`** — Shell script that runs Bandit on all 30 `.py` files and writes the JSON
  reports. Run it with `PATH="$(pwd)/venv/bin:$PATH" bash analysis/run_bandit.sh` from the
  project root.

- **`results_matrix.csv`** — The master findings spreadsheet. Every vulnerability I found across
  all 30 samples is a row here, with columns for LLM, prompt style, task, severity, CWE ID,
  whether Bandit caught it or I found it manually, and notes. This is the primary data source for
  the report.

- **`bandit_summary.csv`** — A condensed version showing HIGH / MEDIUM / LOW counts and CWE IDs
  per sample, generated automatically from the Bandit JSON reports.

- **`generate_figures.py`** — Python script that reads `results_matrix.csv` and produces four
  PNG figures in `figures/`. Run with `venv/bin/python3 analysis/generate_figures.py`.

- **`figures/`** — The four charts output by `generate_figures.py`:
  `bandit_heatmap.png`, `manual_heatmap.png`, `severity_stacked_bar.png`,
  and `bandit_vs_manual_gap.png`.

### `report/`
`findings_notes.md` is where I kept running observations as I worked through the reviews —
patterns I noticed, anything surprising, and draft conclusions. It's informal working notes,
not the final report.

---

## How to Reproduce the Analysis

```bash
# 1. Create the virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Re-run Bandit on all 30 samples
PATH="$(pwd)/venv/bin:$PATH" bash analysis/run_bandit.sh

# 3. Regenerate the summary CSV and figures
venv/bin/python3 analysis/generate_figures.py
```

---

## Author

Name: <!-- Your name here -->  
Institution / Affiliation: <!-- Your institution here -->  
Contact: <!-- Your email here -->  
