"""PII Scanner & Anonymizer implementing Sesi 4 Detect -> Protect -> Verify workflow."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

# Regex patterns for PII detection
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^(?:\+62|62|0)[-\s]?(?:8[1-9][0-9]|[1-9][0-9]{1,2})[-\s0-9]{6,12}$")
NIK_RE = re.compile(r"^(?:1[1-9]|21|[3567][1-9]|8[12]|9[14])[0-9]{14}$")
NPWP_RE = re.compile(r"^\d{2}\.\d{3}\.\d{3}\.\d-\d{3}\.\d{3}$")
IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")
CARD_RE = re.compile(r"^(?:\d[ -]?){13,19}$")

# Column-name keyword heuristics (case-insensitive)
COLUMN_HINTS: List[Tuple[str, str, str, str]] = [
    # (pii_type, risk_level, regex_name_hint, recommended_strategy)
    ("EMAIL", "High", r"(email|e_mail|mail)", "partial"),
    ("PHONE", "High", r"(phone|telp|telepon|no_hp|hp|mobile|whatsapp|wa_num|contact_number)", "partial"),
    ("NIK", "High", r"(^|_)(nik|ktp|no_ktp|national_id|identity_no)($|_)", "sha256"),
    ("NPWP", "High", r"(npwp|tax_id)", "sha256"),
    ("PERSON_NAME", "High", r"(full_name|customer_name|cust_name|user_name|nama|recipient_name|driver_name|first_name|last_name)", "sha256"),
    ("ADDRESS", "High", r"(address|alamat|street|jalan|domisili)", "redact"),
    ("DOB", "Medium", r"(dob|birth_date|tanggal_lahir|tgl_lahir|birthdate)", "redact"),
    ("IP_ADDRESS", "Medium", r"(ip_addr|ip_address|client_ip)", "sha256"),
]

VALUE_DETECTORS: List[Tuple[str, str, re.Pattern[str], str]] = [
    ("EMAIL", "High", EMAIL_RE, "partial"),
    ("PHONE", "High", PHONE_RE, "partial"),
    ("NIK", "High", NIK_RE, "sha256"),
    ("NPWP", "High", NPWP_RE, "sha256"),
    ("IP_ADDRESS", "Medium", IPV4_RE, "sha256"),
]

ADDRESS_VALUE_RE = re.compile(r"\b(jl\.?|jalan|rt\s*\d+|rw\s*\d+|kec\.?|kel\.?|gang|blok)\b", re.IGNORECASE)


def mask_sample_preview(value: Any, pii_type: str) -> str:
    """Return a safe redacted preview of a detected PII value for audit display."""
    text = str(value).strip()
    if not text:
        return ""
    if pii_type == "EMAIL" and "@" in text:
        local, domain = text.split("@", 1)
        prefix = local[:2] if len(local) > 2 else local[:1]
        return f"{prefix}***@{domain}"
    if pii_type in {"PHONE", "NIK", "NPWP", "CARD"}:
        if len(text) <= 4:
            return "*" * len(text)
        return f"{text[:4]}{'*' * max(2, len(text) - 6)}{text[-2:]}"
    if len(text) <= 3:
        return "***"
    return f"{text[:2]}***{text[-1:]}"


def scan_dataframe_pii(df: pd.DataFrame, max_sample: int = 500) -> Dict[str, Any]:
    """Scan all columns of a DataFrame for PII risks using regex + column heuristics."""
    findings: List[Dict[str, Any]] = []
    high_risk_cols: List[str] = []
    medium_risk_cols: List[str] = []

    for col in df.columns:
        series = df[col].dropna().astype(str).str.strip()
        series = series[series != ""]
        non_null_count = int(len(series))
        sample_vals = series.head(max_sample).tolist()

        detected_types: Dict[str, int] = {}
        name_matched_type: Optional[Tuple[str, str, str]] = None

        col_lower = col.lower()
        for pii_type, risk, name_pat, strategy in COLUMN_HINTS:
            if re.search(name_pat, col_lower):
                name_matched_type = (pii_type, risk, strategy)
                break

        # Regex value scan
        if sample_vals:
            for val in sample_vals:
                for pii_type, _risk, pattern, _strat in VALUE_DETECTORS:
                    if pattern.match(val):
                        detected_types[pii_type] = detected_types.get(pii_type, 0) + 1
                if ADDRESS_VALUE_RE.search(val):
                    detected_types["ADDRESS"] = detected_types.get("ADDRESS", 0) + 1

        chosen_type: Optional[str] = None
        chosen_risk = "Low"
        recommended_strategy = "keep"
        detection_source = "none"
        match_count = 0
        match_pct = 0.0

        # Prioritize strong value-based matches (>= 15% of non-null sample)
        if detected_types and sample_vals:
            top_type, top_hits = max(detected_types.items(), key=lambda x: x[1])
            ratio = top_hits / len(sample_vals)
            if ratio >= 0.15:
                chosen_type = top_type
                match_count = int(round(ratio * non_null_count))
                match_pct = round(ratio * 100, 2)
                detection_source = "regex+column_name" if (name_matched_type and name_matched_type[0] == top_type) else "value_pattern"
                for p_type, p_risk, _pat, p_strat in VALUE_DETECTORS:
                    if p_type == top_type:
                        chosen_risk = p_risk
                        recommended_strategy = p_strat
                        break
                if top_type == "ADDRESS":
                    chosen_risk = "High"
                    recommended_strategy = "redact"

        # Fallback to column-name heuristic if value regex didn't cross threshold
        if chosen_type is None and name_matched_type is not None:
            chosen_type, chosen_risk, recommended_strategy = name_matched_type
            detection_source = "column_name_heuristic"
            match_count = non_null_count
            match_pct = 100.0 if non_null_count > 0 else 0.0

        if chosen_type is not None:
            masked_examples = [mask_sample_preview(v, chosen_type) for v in sample_vals[:3]]
            if chosen_risk == "High":
                high_risk_cols.append(col)
            elif chosen_risk == "Medium":
                medium_risk_cols.append(col)

            findings.append({
                "column": col,
                "pii_type": chosen_type,
                "risk_level": chosen_risk,
                "detection_source": detection_source,
                "non_null_count": non_null_count,
                "estimated_affected_count": match_count,
                "estimated_affected_pct": match_pct,
                "recommended_strategy": recommended_strategy,
                "masked_examples": masked_examples,
            })

    overall_status = (
        "ACTION_REQUIRED" if high_risk_cols else ("REVIEW_RECOMMENDED" if medium_risk_cols else "SAFE_NO_PII_DETECTED")
    )

    return {
        "overall_status": overall_status,
        "pii_column_count": len(findings),
        "high_risk_columns": high_risk_cols,
        "medium_risk_columns": medium_risk_cols,
        "findings": findings,
    }


def _hash_value(val: Any, salt: str) -> Optional[str]:
    if pd.isna(val):
        return None
    text = str(val).strip()
    if not text:
        return None
    digest = hashlib.sha256(f"{salt}:{text}".encode("utf-8")).hexdigest()[:12]
    return f"pii_{digest}"


def _partial_mask_value(val: Any, pii_type: str) -> Optional[str]:
    if pd.isna(val):
        return None
    text = str(val).strip()
    if not text:
        return None
    return mask_sample_preview(text, pii_type)


def anonymize_dataframe(
    df: pd.DataFrame,
    column_strategies: Dict[str, str],
    pii_types: Optional[Dict[str, str]] = None,
    salt: str = "raw_profiler_s4_salt",
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Apply masking/anonymization per column and run Sesi 4 Verification Checks (VT-01..VT-03)."""
    pii_types = pii_types or {}
    protected = df.copy()
    applied_rules: List[Dict[str, Any]] = []
    leaks_detected: List[Dict[str, Any]] = []

    for col, strategy in column_strategies.items():
        if col not in protected.columns or strategy == "keep":
            continue
        pii_kind = pii_types.get(col, "GENERIC")

        if strategy == "sha256":
            protected[col] = protected[col].apply(lambda v: _hash_value(v, salt))
        elif strategy == "partial":
            protected[col] = protected[col].apply(lambda v: _partial_mask_value(v, pii_kind))
        elif strategy == "redact":
            protected[col] = protected[col].apply(lambda v: "[REDACTED]" if pd.notna(v) and str(v).strip() != "" else None)
        else:
            raise ValueError(f"Unsupported masking strategy '{strategy}' for column '{col}'.")

        # VT-01: verify no non-empty raw value matches original unmasked value
        orig_series = df[col].dropna().astype(str).str.strip()
        prot_series = protected[col].dropna().astype(str).str.strip()
        overlap = int((orig_series[orig_series != ""] == prot_series.reindex(orig_series[orig_series != ""].index)).sum())
        if overlap > 0:
            leaks_detected.append({"column": col, "raw_leak_count": overlap})

        applied_rules.append({
            "column": col,
            "pii_type": pii_kind,
            "strategy": strategy,
            "rows_transformed": int(orig_series[orig_series != ""].shape[0]),
        })

    row_preserved = len(df) == len(protected)
    col_preserved = list(df.columns) == list(protected.columns)
    vt01_pass = len(leaks_detected) == 0

    verification_evidence = {
        "VT-01_no_raw_pii_leak": {"status": "PASS" if vt01_pass else "FAIL", "leaks": leaks_detected},
        "VT-02_row_count_preserved": {
            "status": "PASS" if row_preserved else "FAIL",
            "before_rows": int(len(df)),
            "after_rows": int(len(protected)),
        },
        "VT-03_schema_preserved": {
            "status": "PASS" if col_preserved else "FAIL",
            "column_count": int(len(protected.columns)),
        },
        "overall_gate": "PASS" if (vt01_pass and row_preserved and col_preserved) else "FAIL",
        "applied_rules": applied_rules,
    }

    return protected, verification_evidence
