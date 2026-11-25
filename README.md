# Raw Data Profiler & PII Scanner

A reusable Data Analyst workbench implementing the **Detect → Measure → Verify** data profiling methodology and **PII Anonymization & Verification Gates (`VT-01`–`VT-03`)** using **FastAPI + DuckDB + pandas** on the backend and **Nuxt 3 + Tailwind CSS** on the frontend.

## Features

- **Multi-Format Loader:** Parses `CSV`, `TSV`, `TXT` (auto-delimiter detection), `XLSX`/`XLS` (multi-sheet selector), `JSON` (nested flattening via `json_normalize`), `Parquet`, and `SQLite`/`DB` (multi-table selector).
- **DuckDB + pandas Profiling:** Computes row/column grain, full-row duplicates, candidate primary keys, missing/blank/placeholder counts, category casing/whitespace inconsistencies, numeric quantiles + IQR outliers, date format mixing, and chronology pair checks.
- **PII Scanner & Anonymizer:** Flags `EMAIL`, `PHONE` (ID/international), `NIK`, `NPWP`, `PERSON_NAME`, `ADDRESS`, `DOB`, and `IP_ADDRESS` via regex + column heuristics, then generates a masked CSV with automated verification evidence (`VT-01`–`VT-03`).
- **Audit Report Export:** Downloads a structured `Markdown` report of all candidate findings (`Candidate — Requires Manual Verification`).

## Running Locally

### 1. Start FastAPI Backend (`http://127.0.0.1:8000`)

```bash
cd tools/raw_data_profiler/backend
.venv/bin/uvicorn app.main:app --reload --port 8000
```

Run backend tests:

```bash
cd tools/raw_data_profiler/backend
.venv/bin/pytest -v
```

### 2. Start Nuxt 3 Frontend (`http://127.0.0.1:3000`)

```bash
cd tools/raw_data_profiler/frontend
npm install
npm run dev
```

To point the frontend at a custom FastAPI URL, set `NUXT_PUBLIC_API_BASE`:

```bash
NUXT_PUBLIC_API_BASE=https://your-api.example.com npm run build
```

## Deploying to Vercel (Single Project via Vercel Services — Beta)

A root `vercel.json` is included to deploy both the Nuxt 3 frontend (`/`) and the FastAPI backend (`/api/*`) in a single Vercel project using **Vercel Services** (in Beta on all Vercel plans).

1. Push the `tools/raw_data_profiler` folder to a GitHub repository.
2. Import the repository in the Vercel dashboard (or run `vercel` inside `tools/raw_data_profiler`).
3. Keep `NUXT_PUBLIC_API_BASE` unset in production so the frontend calls `/api/*` on the same domain.
4. Note: Vercel Functions cap request/response payloads at **4.5 MB** (uploads larger than ~4.5 MB should be tested locally).

