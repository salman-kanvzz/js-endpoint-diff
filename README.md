# js-endpoint-diff

A Python CLI tool that downloads JavaScript files from a list of URLs, extracts **API paths** and **high-entropy strings** (potential secrets/tokens), stores results as a baseline in **SQLite**, and outputs a clean **JSON/Markdown diff** of newly introduced endpoints (and related changes) on subsequent runs.

## Features
- **Input:** JS URLs via `--urls` and/or `--urls-file` (one URL per line, `#` comments supported)
- **Fetching:** downloads JavaScript using **`httpx`** (redirects, configurable timeout)
- **Extraction:** parses JavaScript with **`esprima`** (AST traversal of string/template literals) with regex fallback for robustness on minified/problematic scripts
  - **API paths/endpoints:** heuristic detection of API-like paths and endpoints (e.g. `/api/...`, versioned routes, GraphQL, fetch/axios targets, templated paths)
  - **High-entropy strings:** Shannon-entropy/character-class heuristics to flag likely tokens/keys/secrets (redacted by default in reports)
- **Baseline storage:** persists scans, sources, endpoints, and high-entropy findings in **SQLite** (`jsdiff.db` by default)
- **Diff reporting:** compares current scan vs baseline (latest or specified) and outputs **JSON** and/or **Markdown** diffs highlighting newly introduced/removed endpoints and high-entropy strings
- **History utilities:** list scans, show scan contents, diff stored scans without refetching

> **Note:** Extraction is heuristic-based and may produce false positives/negatives. Always validate findings in an authorized context.

## Project structure
```text
js-endpoint-diff/
├── main.py
├── jsdiff/
│   ├── __init__.py
│   ├── cli.py         # CLI commands (scan, diff, scans, show)
│   ├── fetcher.py     # httpx JS downloader
│   ├── extractor.py   # esprima + regex extraction
│   ├── db.py          # SQLite schema/storage
│   ├── diffing.py     # diff computation and JSON/Markdown rendering
│   └── utils.py       # entropy, normalization, helpers
├── requirements.txt
├── README.md
└── .venv/             # (optional local virtual environment)
```

## Requirements
- Python 3.10+ recommended
- Dependencies: **`httpx`**, **`esprima`** (see `requirements.txt`)

## Setup
```bash
cd js-endpoint-diff

# Option A: virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run
python main.py --help
# or
.venv/bin/python main.py --help
```

## Usage

### 1) Scan and create/update baseline (outputs diff vs previous baseline)
```bash
# First run: creates baseline (no prior baseline to diff against)
python main.py scan --urls https://example.com/app.js --db jsdiff.db --format both --output report

# Using a URLs file
python main.py scan --urls-file urls.txt --db jsdiff.db --format markdown
```

**Scan options:**
- `--urls URL [URL ...]` — JS URLs to fetch
- `--urls-file FILE` — file with one URL per line (`#` comments allowed)
- `--db PATH` — SQLite database path (default: `jsdiff.db`)
- `--timeout SEC` — HTTP timeout (default: 15)
- `--format {json,markdown,both}` — diff output format (default: `both`)
- `--output PATH` — output file, or base path for `both` (writes `.json` and `.md`)
- `--baseline-id ID` — compare against a specific stored scan
- `--no-update-baseline` — compare without storing the new scan
- `--show-secrets` — do not redact high-entropy strings in output
- `--insecure` — disable TLS verification (not recommended)

### 2) List stored scans
```bash
python main.py scans --db jsdiff.db
```

### 3) Show a stored scan
```bash
python main.py show --db jsdiff.db --scan-id 1 --format json
```

### 4) Diff stored scans (no network fetch)
```bash
python main.py diff --db jsdiff.db --from-id 1 --to-id 2 --format both --output diff-1-2
```

## URLs file format (`urls.txt`)
```text
# Production JS bundles
https://target.example/assets/app.js
https://target.example/assets/vendor.js

# Another bundle
https://cdn.example.com/static/chunk.js
```

## Output
- **JSON:** machine-readable diff with summary, `new_endpoints`, `removed_endpoints`, and (redacted by default) high-entropy string changes.
- **Markdown:** clean, readable report emphasizing **newly introduced endpoints**.

Example summary fields: baseline/current scan IDs & timestamps, endpoint counts, new/removed endpoint counts, high-entropy string counts.

## How extraction works
1. **Download:** `httpx.Client` fetches each URL and records status/content.
2. **Parse:** `esprima` parses JS (script/module, tolerant/JSX-enabled) and the AST is walked to collect string and template-literal values.
3. **Classify:** strings are normalized/filtered into likely **API endpoints/paths**; non-endpoint strings are evaluated for **high entropy** (length, Shannon entropy, character diversity) as potential secrets.
4. **Fallback:** regex extraction supplements/covers cases where parsing is partial or source is heavily minified.
5. **Store & diff:** findings are saved per scan in SQLite; diffs compute set differences vs baseline to highlight newly introduced endpoints.

## Ethical use
Use only on applications/assets you own or have explicit permission to test. Do not use extracted endpoints or strings for unauthorized access. Handle any discovered secrets responsibly and avoid exposing them in shared reports (redaction is enabled by default).

## Limitations
- Heuristic endpoint/secret detection can miss obfuscated values or flag benign strings.
- Dynamic/runtime-generated URLs may not appear as static literals.
- Minified bundles may reduce parse fidelity (regex fallback helps but is imperfect).
- Network fetch reflects currently served content only. 
