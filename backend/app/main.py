"""FastAPI entrypoint for Raw Data Profiler & PII Scanner."""
from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse

from .loader import load_dataframe_from_bytes, load_dataframe_from_path
from .pii_scanner import anonymize_dataframe
from .profiler import profile_dataframe, render_markdown_report

APP_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SAMPLE_DIR = APP_ROOT / "sample_data"
if LOCAL_SAMPLE_DIR.is_dir():
    DATA_RAW_DIR = LOCAL_SAMPLE_DIR
elif len(APP_ROOT.parents) > 2:
    DATA_RAW_DIR = APP_ROOT.parents[2] / "data" / "raw"
else:
    DATA_RAW_DIR = LOCAL_SAMPLE_DIR

SAMPLE_CATALOG: Dict[str, Dict[str, str]] = {
    "nusamart_customers": {
        "id": "nusamart_customers",
        "label": "NusaMart Customers (Nested JSON + PII)",
        "rel_path": "nusamart/nusamart_customers.json",
        "description": "Nested JSON customer records with names, emails, and Indonesian phone numbers.",
    },
    "nusamart_orders": {
        "id": "nusamart_orders",
        "label": "NusaMart Orders (Excel XLSX)",
        "rel_path": "nusamart/nusamart_orders.xlsx",
        "description": "Order header spreadsheet for date, status, and amount profiling.",
    },
    "nusamart_order_items": {
        "id": "nusamart_order_items",
        "label": "NusaMart Order Items (CSV)",
        "rel_path": "nusamart/nusamart_order_items.csv",
        "description": "Line-item transaction CSV with composite grain and numeric pricing.",
    },
    "nusamart_payments": {
        "id": "nusamart_payments",
        "label": "NusaMart Payments (Delimited TXT)",
        "rel_path": "nusamart/nusamart_payments.txt",
        "description": "Raw delimited text payment logs for delimiter auto-detection.",
    },
    "mini_orders": {
        "id": "mini_orders",
        "label": "Mini Warehouse Orders (CSV)",
        "rel_path": "orders.csv",
        "description": "Clean baseline transactional orders dataset.",
    },
}

app = FastAPI(
    title="Raw Data Profiler & PII Scanner API",
    version="1.0.0",
    description="DuckDB + pandas Data Profiling (Detect -> Measure -> Verify) and PII Anonymization API.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "engine": "duckdb+pandas"}


@app.get("/api/samples")
def list_samples() -> Dict[str, List[Dict[str, str]]]:
    available = []
    for item in SAMPLE_CATALOG.values():
        path = DATA_RAW_DIR / item["rel_path"]
        if path.is_file():
            available.append({
                "id": item["id"],
                "label": item["label"],
                "description": item["description"],
                "filename": path.name,
            })
    return {"samples": available}


@app.post("/api/profile/sample/{sample_id}")
def profile_sample(
    sample_id: str,
    mask_preview_pii: bool = True,
    sheet_name: Optional[str] = None,
    table_name: Optional[str] = None,
):
    if sample_id not in SAMPLE_CATALOG:
        raise HTTPException(status_code=404, detail=f"Unknown sample_id '{sample_id}'.")
    target = DATA_RAW_DIR / SAMPLE_CATALOG[sample_id]["rel_path"]
    if not target.is_file():
        raise HTTPException(status_code=404, detail=f"Sample file not found: {target.name}")
    df, meta = load_dataframe_from_path(target, sheet_name=sheet_name, table_name=table_name)
    return profile_dataframe(df, source_meta=meta, mask_preview_pii=mask_preview_pii)


@app.post("/api/profile/upload")
async def profile_upload(
    file: UploadFile = File(...),
    mask_preview_pii: bool = Form(True),
    sheet_name: Optional[str] = Form(None),
    table_name: Optional[str] = Form(None),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename.")
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    try:
        df, meta = load_dataframe_from_bytes(
            raw_bytes,
            file.filename,
            sheet_name=sheet_name or None,
            table_name=table_name or None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return profile_dataframe(df, source_meta=meta, mask_preview_pii=mask_preview_pii)


@app.post("/api/anonymize/upload")
async def anonymize_upload(
    file: UploadFile = File(...),
    strategies_json: str = Form(...),
    pii_types_json: str = Form("{}"),
    sheet_name: Optional[str] = Form(None),
    table_name: Optional[str] = Form(None),
):
    """Apply PII masking strategies to an uploaded file and return CSV + verification metadata."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename.")
    raw_bytes = await file.read()
    try:
        strategies = json.loads(strategies_json)
        pii_types = json.loads(pii_types_json)
        df, _meta = load_dataframe_from_bytes(
            raw_bytes,
            file.filename,
            sheet_name=sheet_name or None,
            table_name=table_name or None,
        )
        protected_df, evidence = anonymize_dataframe(df, strategies, pii_types=pii_types)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    csv_buffer = io.StringIO()
    protected_df.to_csv(csv_buffer, index=False)
    safe_name = Path(file.filename).stem + "_safe_masked.csv"

    return {
        "filename": safe_name,
        "verification_evidence": evidence,
        "csv_content": csv_buffer.getvalue(),
    }


@app.post("/api/anonymize/sample/{sample_id}")
def anonymize_sample(
    sample_id: str,
    strategies_json: str = Form(...),
    pii_types_json: str = Form("{}"),
):
    if sample_id not in SAMPLE_CATALOG:
        raise HTTPException(status_code=404, detail=f"Unknown sample_id '{sample_id}'.")
    target = DATA_RAW_DIR / SAMPLE_CATALOG[sample_id]["rel_path"]
    if not target.is_file():
        raise HTTPException(status_code=404, detail="Sample file not found.")
    try:
        strategies = json.loads(strategies_json)
        pii_types = json.loads(pii_types_json)
        df, _meta = load_dataframe_from_path(target)
        protected_df, evidence = anonymize_dataframe(df, strategies, pii_types=pii_types)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    csv_buffer = io.StringIO()
    protected_df.to_csv(csv_buffer, index=False)
    return {
        "filename": f"{sample_id}_safe_masked.csv",
        "verification_evidence": evidence,
        "csv_content": csv_buffer.getvalue(),
    }


@app.post("/api/report/markdown", response_class=PlainTextResponse)
async def export_markdown_report(
    file: Optional[UploadFile] = File(None),
    sample_id: Optional[str] = Form(None),
):
    if file is not None and file.filename:
        raw_bytes = await file.read()
        df, meta = load_dataframe_from_bytes(raw_bytes, file.filename)
    elif sample_id:
        if sample_id not in SAMPLE_CATALOG:
            raise HTTPException(status_code=404, detail=f"Unknown sample_id '{sample_id}'.")
        target = DATA_RAW_DIR / SAMPLE_CATALOG[sample_id]["rel_path"]
        df, meta = load_dataframe_from_path(target)
    else:
        raise HTTPException(status_code=400, detail="Provide either 'file' or 'sample_id'.")

    report = profile_dataframe(df, source_meta=meta, mask_preview_pii=True)
    md_text = render_markdown_report(report)
    return StreamingResponse(
        io.BytesIO(md_text.encode("utf-8")),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{Path(meta["filename"]).stem}_audit_report.md"'},
    )
