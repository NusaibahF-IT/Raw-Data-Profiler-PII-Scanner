"""Multi-format raw data loader supporting CSV, TSV/TXT, Excel, JSON, Parquet, and SQLite."""
from __future__ import annotations

import csv
import io
import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

SUPPORTED_EXTENSIONS = {".csv", ".tsv", ".txt", ".xlsx", ".xls", ".json", ".parquet", ".sqlite", ".db"}

PLACEHOLDER_VALUES = {"", "na", "n/a", "null", "none", "nan", "-", "--", "unknown", "undefined"}


def _decode_bytes(raw_bytes: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "latin1", "cp1252"):
        try:
            return raw_bytes.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def _detect_delimiter(sample_text: str) -> str:
    lines = [ln for ln in sample_text.splitlines()[:20] if ln.strip()]
    snippet = "\n".join(lines)
    try:
        dialect = csv.Sniffer().sniff(snippet, delimiters=",;\t|")
        return dialect.delimiter
    except csv.Error:
        counts = {d: snippet.count(d) for d in (",", ";", "\t", "|")}
        best = max(counts, key=counts.get)
        return best if counts[best] > 0 else ","


def _normalize_json_records(payload: Any) -> pd.DataFrame:
    if isinstance(payload, list):
        return pd.json_normalize(payload, sep=".")
    if isinstance(payload, dict):
        for key, val in payload.items():
            if isinstance(val, list) and len(val) > 0 and isinstance(val[0], dict):
                return pd.json_normalize(val, sep=".")
        return pd.json_normalize([payload], sep=".")
    raise ValueError("Unsupported JSON structure: expected array of objects or object.")


def load_dataframe_from_bytes(
    raw_bytes: bytes,
    filename: str,
    sheet_name: Optional[str] = None,
    table_name: Optional[str] = None,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Load an uploaded file into a pandas DataFrame along with source metadata."""
    ext = Path(filename).suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file extension '{ext}'. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        )

    meta: Dict[str, Any] = {
        "filename": Path(filename).name,
        "format": ext.lstrip("."),
        "size_bytes": len(raw_bytes),
        "available_sheets_or_tables": [],
        "selected_source": None,
    }

    if ext in {".csv", ".tsv", ".txt"}:
        text = _decode_bytes(raw_bytes)
        delim = "\t" if ext == ".tsv" else _detect_delimiter(text)
        df = pd.read_csv(io.StringIO(text), sep=delim, dtype_backend="numpy_nullable", keep_default_na=True)
        meta["delimiter"] = repr(delim)

    elif ext in {".xlsx", ".xls"}:
        xl = pd.ExcelFile(io.BytesIO(raw_bytes))
        meta["available_sheets_or_tables"] = xl.sheet_names
        chosen = sheet_name if (sheet_name and sheet_name in xl.sheet_names) else xl.sheet_names[0]
        meta["selected_source"] = chosen
        df = xl.parse(chosen)

    elif ext == ".json":
        text = _decode_bytes(raw_bytes).strip()
        try:
            payload = json.loads(text)
            df = _normalize_json_records(payload)
        except json.JSONDecodeError:
            # Fallback to JSON Lines
            df = pd.read_json(io.StringIO(text), lines=True)

    elif ext == ".parquet":
        df = pd.read_parquet(io.BytesIO(raw_bytes))

    elif ext in {".sqlite", ".db"}:
        with tempfile.NamedTemporaryFile(suffix=ext, delete=True) as tmp:
            tmp.write(raw_bytes)
            tmp.flush()
            conn = sqlite3.connect(tmp.name)
            try:
                tables_df = pd.read_sql_query(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
                    conn,
                )
                tables: List[str] = tables_df["name"].tolist()
                if not tables:
                    raise ValueError("SQLite database contains no user tables.")
                meta["available_sheets_or_tables"] = tables
                chosen = table_name if (table_name and table_name in tables) else tables[0]
                meta["selected_source"] = chosen
                safe_ident = chosen.replace('"', '""')
                df = pd.read_sql_query(f'SELECT * FROM "{safe_ident}"', conn)
            finally:
                conn.close()
    else:
        raise ValueError(f"Unsupported format: {ext}")

    # Normalize column names to strings and strip outer spaces while preserving audit notice if renamed
    original_cols = [str(c) for c in df.columns]
    df.columns = [str(c).strip() if str(c).strip() else f"unnamed_col_{i}" for i, c in enumerate(original_cols)]
    return df, meta


def load_dataframe_from_path(
    file_path: Path,
    sheet_name: Optional[str] = None,
    table_name: Optional[str] = None,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    raw_bytes = Path(file_path).read_bytes()
    return load_dataframe_from_bytes(raw_bytes, file_path.name, sheet_name=sheet_name, table_name=table_name)
