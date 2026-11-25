"""DuckDB + pandas Raw Data Profiling engine following Detect -> Measure -> Verify."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

import duckdb
import pandas as pd

from .loader import PLACEHOLDER_VALUES
from .pii_scanner import mask_sample_preview, scan_dataframe_pii

NUMERIC_STRING_RE = re.compile(r"^(?:rp\.?|idr|\$|€)?\s*-?\d[\d.,\s]*$", re.IGNORECASE)
DATE_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("ISO (YYYY-MM-DD)", re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}:\d{2}(?::\d{2})?)?")),
    ("Slash DMY/MDY (DD/MM/YYYY)", re.compile(r"^\d{1,2}/\d{1,2}/\d{2,4}$")),
    ("Dash DMY (DD-MM-YYYY)", re.compile(r"^\d{1,2}-\d{1,2}-\d{4}$")),
    ("Text Month", re.compile(r"^\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4}$")),
]


def _safe_float(val: Any) -> Optional[float]:
    if val is None or pd.isna(val):
        return None
    try:
        return round(float(val), 4)
    except (TypeError, ValueError):
        return None


def _detect_date_formats(values: List[str]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for val in values:
        matched = False
        for label, pat in DATE_PATTERNS:
            if pat.match(val):
                counts[label] = counts.get(label, 0) + 1
                matched = True
                break
        if not matched:
            counts["Other"] = counts.get("Other", 0) + 1
    return counts


def _infer_semantic_type(series: pd.Series, col_name: str) -> str:
    if pd.api.types.is_bool_dtype(series):
        return "boolean"
    if pd.api.types.is_numeric_dtype(series):
        return "numeric"
    if pd.api.types.is_datetime64_any_dtype(series):
        return "datetime"

    non_null = series.dropna().astype(str).str.strip()
    non_null = non_null[non_null != ""]
    if len(non_null) == 0:
        return "empty"

    sample = non_null.head(300)
    if any(k in col_name.lower() for k in ("date", "tgl", "tanggal", "time", "created_at", "updated_at")):
        parsed = pd.to_datetime(sample, errors="coerce", format="mixed")
        if parsed.notna().mean() >= 0.7:
            return "datetime_text"

    # Check if text looks like numeric formatted with currency/commas
    num_hits = sample.apply(lambda v: bool(NUMERIC_STRING_RE.match(v))).mean()
    if num_hits >= 0.8 and not any(k in col_name.lower() for k in ("phone", "hp", "nik", "id", "zip", "kode")):
        return "numeric_text"

    parsed_dt = pd.to_datetime(sample, errors="coerce", format="mixed")
    if parsed_dt.notna().mean() >= 0.85:
        return "datetime_text"

    return "categorical_or_text"


def _pick_reference_key_col(df: pd.DataFrame, col_profiles: List[Dict[str, Any]]) -> Optional[str]:
    for cp in col_profiles:
        if cp["is_candidate_key"]:
            return cp["column"]
    for col in df.columns:
        if col.lower().endswith("_id") or col.lower() == "id":
            return col
    return None


def _sample_keys(df: pd.DataFrame, mask: pd.Series, key_col: Optional[str], limit: int = 3) -> List[str]:
    if not mask.any():
        return []
    sub = df.loc[mask]
    if key_col and key_col in sub.columns:
        return [str(v) for v in sub[key_col].head(limit).tolist()]
    return [f"row#{int(idx) + 1}" for idx in sub.index[:limit]]


def profile_dataframe(
    df: pd.DataFrame,
    source_meta: Optional[Dict[str, Any]] = None,
    mask_preview_pii: bool = True,
) -> Dict[str, Any]:
    """Run full Detect -> Measure -> Verify profiling using DuckDB + pandas."""
    source_meta = source_meta or {}
    row_count = int(len(df))
    col_count = int(len(df.columns))
    memory_kb = round(float(df.memory_usage(deep=True).sum()) / 1024.0, 2)
    full_row_duplicates = int(df.duplicated().sum()) if row_count > 0 else 0

    # Register DataFrame in DuckDB for fast SQL aggregations
    con = duckdb.connect(database=":memory:")
    # Normalize object columns with mixed types to string before DuckDB registration
    reg_df = df.copy()
    for c in reg_df.columns:
        if reg_df[c].dtype == "object":
            reg_df[c] = reg_df[c].where(reg_df[c].notna(), None)
            reg_df[c] = reg_df[c].apply(lambda x: str(x) if x is not None else None)
    con.register("raw_data", reg_df)

    pii_report = scan_dataframe_pii(df)
    pii_by_col = {f["column"]: f for f in pii_report["findings"]}

    column_profiles: List[Dict[str, Any]] = []
    candidate_findings: List[Dict[str, Any]] = []
    finding_seq = 1

    def add_finding(
        severity: str,
        area: str,
        field: str,
        description: str,
        count_affected: int,
        sample_keys: List[str],
        evidence: str,
    ) -> None:
        nonlocal finding_seq
        pct = round((count_affected / row_count) * 100, 2) if row_count > 0 else 0.0
        candidate_findings.append({
            "finding_id": f"FND-{finding_seq:03d}",
            "severity": severity,
            "area": area,
            "field": field,
            "description": description,
            "count_affected": int(count_affected),
            "pct_affected": pct,
            "sample_record_keys": sample_keys,
            "evidence": evidence,
            "status": "Candidate — Requires Manual Verification",
        })
        finding_seq += 1

    # Pass 1: Column-level metrics via DuckDB + pandas
    for col in df.columns:
        quoted = f'"{col.replace(chr(34), chr(34) * 2)}"'
        series = df[col]
        semantic_type = _infer_semantic_type(series, col)

        if row_count > 0:
            stats_row = con.execute(
                f"""
                SELECT
                    COUNT(*) - COUNT({quoted}) AS null_count,
                    COUNT(DISTINCT {quoted}) AS distinct_count
                FROM raw_data
                """
            ).fetchone()
            null_count = int(stats_row[0])
            distinct_count = int(stats_row[1])
        else:
            null_count = 0
            distinct_count = 0

        # Blank / placeholder checks on stringified values
        str_series = series.dropna().astype(str).str.strip()
        blank_count = int((str_series == "").sum())
        placeholder_count = int(str_series.str.lower().isin(PLACEHOLDER_VALUES - {""}).sum())
        effective_missing = null_count + blank_count + placeholder_count
        missing_pct = round((effective_missing / row_count) * 100, 2) if row_count > 0 else 0.0

        non_null_count = row_count - null_count - blank_count
        duplicate_count = max(0, non_null_count - distinct_count) if non_null_count > 0 else 0
        uniqueness_ratio = round((distinct_count / non_null_count), 4) if non_null_count > 0 else 0.0
        is_candidate_key = bool(
            non_null_count > 0
            and null_count == 0
            and blank_count == 0
            and distinct_count == row_count
            and semantic_type not in {"numeric", "boolean"}
        )

        # Numeric statistics
        numeric_stats: Optional[Dict[str, Any]] = None
        if semantic_type == "numeric" and non_null_count > 0:
            num_row = con.execute(
                f"""
                SELECT
                    MIN(CAST({quoted} AS DOUBLE)),
                    QUANTILE_CONT(CAST({quoted} AS DOUBLE), 0.25),
                    MEDIAN(CAST({quoted} AS DOUBLE)),
                    QUANTILE_CONT(CAST({quoted} AS DOUBLE), 0.75),
                    MAX(CAST({quoted} AS DOUBLE)),
                    AVG(CAST({quoted} AS DOUBLE)),
                    STDDEV_SAMP(CAST({quoted} AS DOUBLE)),
                    SUM(CASE WHEN CAST({quoted} AS DOUBLE) < 0 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN CAST({quoted} AS DOUBLE) = 0 THEN 1 ELSE 0 END)
                FROM raw_data
                WHERE {quoted} IS NOT NULL
                """
            ).fetchone()
            q25 = _safe_float(num_row[1])
            q75 = _safe_float(num_row[3])
            iqr = (q75 - q25) if (q25 is not None and q75 is not None) else None
            outlier_count = 0
            if iqr is not None and iqr > 0:
                lower = q25 - 1.5 * iqr
                upper = q75 + 1.5 * iqr
                outlier_count = int(((series < lower) | (series > upper)).sum())

            numeric_stats = {
                "min": _safe_float(num_row[0]),
                "p25": q25,
                "median": _safe_float(num_row[2]),
                "p75": q75,
                "max": _safe_float(num_row[4]),
                "mean": _safe_float(num_row[5]),
                "std": _safe_float(num_row[6]),
                "negative_count": int(num_row[7] or 0),
                "zero_count": int(num_row[8] or 0),
                "iqr_outlier_count": outlier_count,
            }

        # Date statistics
        date_stats: Optional[Dict[str, Any]] = None
        if semantic_type in {"datetime", "datetime_text"} and non_null_count > 0:
            non_empty_str = str_series[str_series != ""]
            parsed = pd.to_datetime(series, errors="coerce", format="mixed")
            valid_dates = parsed.dropna()
            unparseable_count = int(non_null_count - len(valid_dates))
            format_mix = _detect_date_formats(non_empty_str.head(500).tolist())
            date_stats = {
                "min_date": str(valid_dates.min())[:19] if len(valid_dates) > 0 else None,
                "max_date": str(valid_dates.max())[:19] if len(valid_dates) > 0 else None,
                "unparseable_count": max(0, unparseable_count),
                "format_variants": format_mix,
            }

        # Top values & categorical consistency
        top_values: List[Dict[str, Any]] = []
        case_whitespace_variants: List[List[str]] = []
        if non_null_count > 0:
            vc = str_series[str_series != ""].value_counts().head(5)
            pii_info = pii_by_col.get(col)
            for val, cnt in vc.items():
                display_val = mask_sample_preview(val, pii_info["pii_type"]) if (pii_info and mask_preview_pii) else str(val)
                top_values.append({"value": display_val, "count": int(cnt)})

            if semantic_type == "categorical_or_text" and distinct_count <= 200:
                unique_vals = str_series[str_series != ""].unique().tolist()
                groups: Dict[str, List[str]] = {}
                for uv in unique_vals:
                    norm = re.sub(r"\s+", " ", uv.strip().lower())
                    groups.setdefault(norm, []).append(uv)
                case_whitespace_variants = [v for v in groups.values() if len(v) > 1][:5]

        # Also check raw outer whitespace on non-null strings
        leading_trailing_ws = int(series.dropna().astype(str).apply(lambda s: s != s.strip()).sum())

        column_profiles.append({
            "column": col,
            "pandas_dtype": str(series.dtype),
            "semantic_type": semantic_type,
            "null_count": null_count,
            "blank_count": blank_count,
            "placeholder_count": placeholder_count,
            "effective_missing": effective_missing,
            "missing_pct": missing_pct,
            "distinct_count": distinct_count,
            "duplicate_count": duplicate_count,
            "uniqueness_ratio": uniqueness_ratio,
            "is_candidate_key": is_candidate_key,
            "leading_trailing_whitespace": leading_trailing_ws,
            "case_variants": case_whitespace_variants,
            "numeric_stats": numeric_stats,
            "date_stats": date_stats,
            "top_values": top_values,
            "pii_info": pii_by_col.get(col),
        })

    con.close()

    # Pass 2: Generate structured Candidate Findings (Detect -> Measure -> Verify)
    ref_key_col = _pick_reference_key_col(df, column_profiles)

    if full_row_duplicates > 0:
        dup_mask = df.duplicated(keep=False)
        add_finding(
            severity="High",
            area="Duplicate Rows",
            field="(entire row)",
            description=f"Found {full_row_duplicates} exact duplicate row(s) across all columns.",
            count_affected=full_row_duplicates,
            sample_keys=_sample_keys(df, dup_mask, ref_key_col),
            evidence=f"exact_duplicates={full_row_duplicates}, total_rows={row_count}",
        )

    for cp in column_profiles:
        col = cp["column"]
        series = df[col]

        # Missing / blank / placeholder finding
        if cp["effective_missing"] > 0:
            str_s = series.fillna("").astype(str).str.strip().str.lower()
            miss_mask = series.isna() | str_s.isin(PLACEHOLDER_VALUES)
            sev = "High" if cp["missing_pct"] >= 10.0 else ("Medium" if cp["missing_pct"] > 0 else "Low")
            add_finding(
                severity=sev,
                area="Missing / Blank",
                field=col,
                description=f"Column '{col}' has {cp['effective_missing']} missing/blank/placeholder value(s) ({cp['missing_pct']}%).",
                count_affected=cp["effective_missing"],
                sample_keys=_sample_keys(df, miss_mask, ref_key_col),
                evidence=f"null={cp['null_count']}, blank={cp['blank_count']}, placeholder={cp['placeholder_count']}",
            )

        # Candidate key duplicate check for *_id columns
        if (col.lower().endswith("_id") or col.lower() == "id") and cp["duplicate_count"] > 0:
            dup_id_mask = series.notna() & series.duplicated(keep=False)
            add_finding(
                severity="High",
                area="Candidate Key",
                field=col,
                description=f"Identifier column '{col}' is not unique: {cp['duplicate_count']} duplicate occurrence(s).",
                count_affected=cp["duplicate_count"],
                sample_keys=_sample_keys(df, dup_id_mask, col),
                evidence=f"distinct={cp['distinct_count']}, non_null={row_count - cp['null_count']}",
            )

        # Whitespace or inconsistent category casing
        if cp["leading_trailing_whitespace"] > 0:
            ws_mask = series.notna() & series.astype(str).apply(lambda s: s != s.strip())
            add_finding(
                severity="Low",
                area="Category Consistency",
                field=col,
                description=f"Column '{col}' contains {cp['leading_trailing_whitespace']} value(s) with leading/trailing whitespace.",
                count_affected=cp["leading_trailing_whitespace"],
                sample_keys=_sample_keys(df, ws_mask, ref_key_col),
                evidence=f"whitespace_rows={cp['leading_trailing_whitespace']}",
            )

        if cp["case_variants"]:
            flat_variants = [item for grp in cp["case_variants"] for item in grp]
            var_mask = series.astype(str).isin(flat_variants)
            add_finding(
                severity="Medium",
                area="Category Consistency",
                field=col,
                description=f"Inconsistent casing/spacing labels detected in '{col}' (e.g. {cp['case_variants'][0]}).",
                count_affected=int(var_mask.sum()),
                sample_keys=_sample_keys(df, var_mask, ref_key_col),
                evidence=f"variant_groups={cp['case_variants'][:3]}",
            )

        # Numeric stored as text
        if cp["semantic_type"] == "numeric_text":
            non_null_mask = series.notna() & (series.astype(str).str.strip() != "")
            add_finding(
                severity="Medium",
                area="Data Type / Numeric",
                field=col,
                description=f"Column '{col}' contains numeric values stored as formatted text (e.g. currency/commas).",
                count_affected=int(non_null_mask.sum()),
                sample_keys=_sample_keys(df, non_null_mask, ref_key_col),
                evidence=f"pandas_dtype={cp['pandas_dtype']}, sample={[v['value'] for v in cp['top_values'][:2]]}",
            )

        # Negative values or IQR outliers
        if cp["numeric_stats"]:
            ns = cp["numeric_stats"]
            if ns["negative_count"] > 0:
                neg_mask = pd.to_numeric(series, errors="coerce") < 0
                add_finding(
                    severity="Medium",
                    area="Numeric / Range",
                    field=col,
                    description=f"Column '{col}' contains {ns['negative_count']} negative value(s) (min={ns['min']}).",
                    count_affected=ns["negative_count"],
                    sample_keys=_sample_keys(df, neg_mask, ref_key_col),
                    evidence=f"min={ns['min']}, max={ns['max']}, negative_count={ns['negative_count']}",
                )
            if ns["iqr_outlier_count"] > 0:
                add_finding(
                    severity="Low",
                    area="Numeric / Outlier",
                    field=col,
                    description=f"Column '{col}' has {ns['iqr_outlier_count']} statistical IQR outlier(s) requiring domain verification.",
                    count_affected=ns["iqr_outlier_count"],
                    sample_keys=[],
                    evidence=f"p25={ns['p25']}, median={ns['median']}, p75={ns['p75']}, max={ns['max']}",
                )

        # Date format mixing / unparseable dates
        if cp["date_stats"]:
            ds = cp["date_stats"]
            if ds["unparseable_count"] > 0:
                parsed = pd.to_datetime(series, errors="coerce", format="mixed")
                bad_dt_mask = series.notna() & (series.astype(str).str.strip() != "") & parsed.isna()
                add_finding(
                    severity="High",
                    area="Date / Parseability",
                    field=col,
                    description=f"Column '{col}' has {ds['unparseable_count']} unparseable date value(s).",
                    count_affected=ds["unparseable_count"],
                    sample_keys=_sample_keys(df, bad_dt_mask, ref_key_col),
                    evidence=f"unparseable={ds['unparseable_count']}",
                )
            non_other_formats = {k: v for k, v in ds["format_variants"].items() if k != "Other"}
            if len(non_other_formats) > 1:
                add_finding(
                    severity="Medium",
                    area="Date / Format Mix",
                    field=col,
                    description=f"Column '{col}' mixes multiple date string formats: {list(non_other_formats.keys())}.",
                    count_affected=sum(non_other_formats.values()),
                    sample_keys=[],
                    evidence=f"formats={ds['format_variants']}",
                )

        # PII Risk finding
        if cp["pii_info"]:
            pi = cp["pii_info"]
            add_finding(
                severity=pi["risk_level"],
                area="PII Risk",
                field=col,
                description=f"Potential {pi['pii_type']} PII detected via {pi['detection_source']} (recommended: {pi['recommended_strategy']}).",
                count_affected=pi["estimated_affected_count"],
                sample_keys=[],
                evidence=f"masked_samples={pi['masked_examples']}",
            )

    # Chronology pair check (e.g. order_date vs delivery_date / shipped_date / join_date)
    date_cols = [cp["column"] for cp in column_profiles if cp["date_stats"] is not None]
    pair_rules = [("order", "deliver"), ("order", "ship"), ("start", "end"), ("signup", "order"), ("created", "updated")]
    for start_kw, end_kw in pair_rules:
        starts = [c for c in date_cols if start_kw in c.lower()]
        ends = [c for c in date_cols if end_kw in c.lower()]
        for sc in starts:
            for ec in ends:
                if sc == ec:
                    continue
                s_dt = pd.to_datetime(df[sc], errors="coerce", format="mixed")
                e_dt = pd.to_datetime(df[ec], errors="coerce", format="mixed")
                bad_chrono = s_dt.notna() & e_dt.notna() & (e_dt < s_dt)
                cnt = int(bad_chrono.sum())
                if cnt > 0:
                    add_finding(
                        severity="High",
                        area="Date / Chronology",
                        field=f"{sc} -> {ec}",
                        description=f"Chronology anomaly: '{ec}' is earlier than '{sc}' in {cnt} row(s).",
                        count_affected=cnt,
                        sample_keys=_sample_keys(df, bad_chrono, ref_key_col),
                        evidence=f"anomalous_rows={cnt}",
                    )

    # Compute Data Readiness Score (0-100)
    high_cnt = sum(1 for f in candidate_findings if f["severity"] == "High" and f["area"] != "PII Risk")
    med_cnt = sum(1 for f in candidate_findings if f["severity"] == "Medium" and f["area"] != "PII Risk")
    avg_missing_pct = sum(cp["missing_pct"] for cp in column_profiles) / col_count if col_count > 0 else 0.0
    readiness_score = max(0, round(100 - (high_cnt * 12) - (med_cnt * 5) - (avg_missing_pct * 0.5)))

    # Safe sample rows preview (mask PII columns if requested)
    preview_df = df.head(8).copy()
    if mask_preview_pii:
        for col, pi in pii_by_col.items():
            if col in preview_df.columns:
                preview_df[col] = preview_df[col].apply(
                    lambda v: mask_sample_preview(v, pi["pii_type"]) if pd.notna(v) and str(v).strip() else None
                )
    preview_rows = preview_df.where(preview_df.notna(), None).to_dict(orient="records")

    return {
        "source": source_meta,
        "overview": {
            "row_count": row_count,
            "column_count": col_count,
            "memory_kb": memory_kb,
            "full_row_duplicates": full_row_duplicates,
            "candidate_key_columns": [cp["column"] for cp in column_profiles if cp["is_candidate_key"]],
            "data_readiness_score": readiness_score,
            "findings_summary": {
                "total": len(candidate_findings),
                "high": sum(1 for f in candidate_findings if f["severity"] == "High"),
                "medium": sum(1 for f in candidate_findings if f["severity"] == "Medium"),
                "low": sum(1 for f in candidate_findings if f["severity"] == "Low"),
            },
        },
        "pii_summary": pii_report,
        "columns": column_profiles,
        "candidate_findings": candidate_findings,
        "preview_rows": preview_rows,
    }


def render_markdown_report(report: Dict[str, Any]) -> str:
    """Render a Detect -> Measure -> Verify Markdown report matching Sesi 2 & Sesi 4 deliverables."""
    src = report.get("source", {})
    ov = report.get("overview", {})
    pii = report.get("pii_summary", {})
    lines = [
        f"# Raw Data Profiling & PII Audit Report — `{src.get('filename', 'dataset')}`",
        "",
        "Generated using the **Detect → Measure → Verify** methodology.",
        "",
        "## 1. Dataset Overview",
        f"- **Rows:** {ov.get('row_count', 0)}",
        f"- **Columns:** {ov.get('column_count', 0)}",
        f"- **Memory:** {ov.get('memory_kb', 0)} KB",
        f"- **Full-Row Duplicates:** {ov.get('full_row_duplicates', 0)}",
        f"- **Candidate Key(s):** {', '.join(ov.get('candidate_key_columns', [])) or 'None detected'}",
        f"- **Data Readiness Score:** {ov.get('data_readiness_score', 0)} / 100",
        "",
        "## 2. PII Risk Summary",
        f"- **Overall PII Status:** `{pii.get('overall_status', 'UNKNOWN')}`",
        f"- **High Risk Columns:** {', '.join(pii.get('high_risk_columns', [])) or 'None'}",
        f"- **Medium Risk Columns:** {', '.join(pii.get('medium_risk_columns', [])) or 'None'}",
        "",
        "## 3. Candidate Findings (Requires Manual Verification)",
        "",
        "| ID | Severity | Area | Field | Affected | Sample Keys | Description |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for f in report.get("candidate_findings", []):
        keys = ", ".join(f.get("sample_record_keys", [])) or "-"
        lines.append(
            f"| {f['finding_id']} | {f['severity']} | {f['area']} | `{f['field']}` | "
            f"{f['count_affected']} ({f['pct_affected']}%) | {keys} | {f['description']} |"
        )
    if not report.get("candidate_findings"):
        lines.append("| - | - | - | - | - | - | No anomalies or PII risks detected. |")
    lines.append("")
    return "\n".join(lines)
