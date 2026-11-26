"""Unit and API tests for Raw Data Profiler & PII Scanner."""
from __future__ import annotations

import io
import json
import sqlite3
import tempfile
from pathlib import Path

import pandas as pd
from fastapi.testclient import TestClient

from app.loader import load_dataframe_from_bytes
from app.main import app
from app.pii_scanner import anonymize_dataframe, scan_dataframe_pii
from app.profiler import profile_dataframe, render_markdown_report

client = TestClient(app)


def test_pii_detection_and_anonymization_verification():
    df = pd.DataFrame({
        "customer_id": ["C001", "C002", "C003"],
        "customer_name": ["Wahyu Utami", "Nina Nugraha", "Omar Lestari"],
        "email": ["wahyu@example.com", "nina@example.com", "omar@example.com"],
        "phone": ["081210007919", "+6281312345678", "085611122233"],
        "nik": ["3171012345670001", "3273012345670002", "3374012345670003"],
        "city": ["Jakarta", "jakarta ", "Bandung"],
        "spend": [125000, -5000, 300000],
    })

    pii = scan_dataframe_pii(df)
    detected_cols = {f["column"]: f["pii_type"] for f in pii["findings"]}
    assert detected_cols["email"] == "EMAIL"
    assert detected_cols["phone"] == "PHONE"
    assert detected_cols["nik"] == "NIK"
    assert detected_cols["customer_name"] == "PERSON_NAME"
    assert pii["overall_status"] == "ACTION_REQUIRED"

    protected, evidence = anonymize_dataframe(
        df,
        column_strategies={
            "customer_name": "sha256",
            "email": "partial",
            "phone": "partial",
            "nik": "redact",
        },
        pii_types=detected_cols,
    )
    assert evidence["overall_gate"] == "PASS"
    assert evidence["VT-01_no_raw_pii_leak"]["status"] == "PASS"
    assert evidence["VT-02_row_count_preserved"]["status"] == "PASS"
    assert protected["nik"].tolist() == ["[REDACTED]", "[REDACTED]", "[REDACTED]"]
    assert all(v.startswith("pii_") for v in protected["customer_name"])
    assert "wahyu@example.com" not in protected["email"].tolist()


def test_profiler_detects_anomalies_and_chronology():
    df = pd.DataFrame({
        "order_id": ["ORD-1", "ORD-1", "ORD-2", "ORD-3"],
        "order_date": ["2026-07-10", "2026-07-10", "15/07/2026", "bad-date"],
        "delivery_date": ["2026-07-08", "2026-07-08", "2026-07-18", "2026-07-20"],
        "city": ["Jakarta", "Jakarta", "jakarta", "N/A"],
        "amount": [10000, 10000, -250, 50000],
    })
    report = profile_dataframe(df, source_meta={"filename": "test_orders.csv"})
    areas = {f["area"] for f in report["candidate_findings"]}

    assert "Duplicate Rows" in areas
    assert "Candidate Key" in areas
    assert "Missing / Blank" in areas
    assert "Category Consistency" in areas
    assert "Numeric / Range" in areas
    assert "Date / Parseability" in areas
    assert "Date / Format Mix" in areas
    assert "Date / Chronology" in areas

    md = render_markdown_report(report)
    assert "Detect → Measure → Verify" in md
    assert "test_orders.csv" in md


def test_loader_json_nested_and_sqlite():
    nested_json = json.dumps([
        {"id": 1, "profile": {"name": "Ayu", "email": "ayu@example.com"}},
        {"id": 2, "profile": {"name": "Budi", "email": "budi@example.com"}},
    ]).encode("utf-8")
    df_json, meta_json = load_dataframe_from_bytes(nested_json, "customers.json")
    assert "profile.email" in df_json.columns
    assert meta_json["format"] == "json"

    with tempfile.NamedTemporaryFile(suffix=".sqlite") as tmp:
        conn = sqlite3.connect(tmp.name)
        conn.execute("CREATE TABLE orders (order_id TEXT, total REAL)")
        conn.execute("INSERT INTO orders VALUES ('O1', 15000.0)")
        conn.commit()
        conn.close()
        sqlite_bytes = Path(tmp.name).read_bytes()

    df_sql, meta_sql = load_dataframe_from_bytes(sqlite_bytes, "store.sqlite")
    assert meta_sql["selected_source"] == "orders"
    assert len(df_sql) == 1


def test_fastapi_upload_and_anonymize_endpoints():
    csv_data = (
        "customer_id,customer_name,email,phone,city\n"
        "C1,Rina Sari,rina@example.com,081234567890,Jakarta\n"
        "C2,Doni Pratama,doni@example.com,081298765432,Bandung\n"
    ).encode("utf-8")

    resp = client.post(
        "/api/profile/upload",
        files={"file": ("clients.csv", io.BytesIO(csv_data), "text/csv")},
        data={"mask_preview_pii": "true"},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["overview"]["row_count"] == 2
    assert "email" in payload["pii_summary"]["high_risk_columns"]
    # Preview must mask raw email
    assert payload["preview_rows"][0]["email"] != "rina@example.com"

    anon_resp = client.post(
        "/api/anonymize/upload",
        files={"file": ("clients.csv", io.BytesIO(csv_data), "text/csv")},
        data={
            "strategies_json": json.dumps({"customer_name": "sha256", "email": "partial", "phone": "redact"}),
            "pii_types_json": json.dumps({"customer_name": "PERSON_NAME", "email": "EMAIL", "phone": "PHONE"}),
        },
    )
    assert anon_resp.status_code == 200
    anon_payload = anon_resp.json()
    assert anon_payload["verification_evidence"]["overall_gate"] == "PASS"
    assert "rina@example.com" not in anon_payload["csv_content"]


def test_bootcamp_sample_catalog_and_nusamart_customers():
    samples_resp = client.get("/api/samples")
    assert samples_resp.status_code == 200
    sample_ids = {s["id"] for s in samples_resp.json()["samples"]}
    assert "nusamart_customers" in sample_ids

    prof_resp = client.post("/api/profile/sample/nusamart_customers?mask_preview_pii=true")
    assert prof_resp.status_code == 200
    data = prof_resp.json()
    assert data["overview"]["row_count"] > 0
    assert data["pii_summary"]["overall_status"] == "ACTION_REQUIRED"
    assert any("email" in c for c in data["pii_summary"]["high_risk_columns"])


def test_nullable_numeric_and_boolean_csv_with_missing_values():
    csv_bytes = (
        "order_id,promo_code,delay_minutes,is_late,order_timestamp\n"
        "O1,, -14.0,False,2026-03-24 09:05:00\n"
        "O2,HEMAT15,,True,2026-03-25 10:15:00\n"
        "O3,SAVE10,5.5,,2026-03-26 11:00:00\n"
    ).encode("utf-8")
    resp = client.post(
        "/api/profile/upload",
        files={"file": ("nullable_test.csv", io.BytesIO(csv_bytes), "text/csv")},
        data={"mask_preview_pii": "true"},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["overview"]["row_count"] == 3
    assert payload["preview_rows"][1]["delay_minutes"] is None
    assert payload["preview_rows"][2]["is_late"] is None


def test_owner_access_guard_blocks_public_upload_but_allows_samples(monkeypatch):
    # Fail-closed on Vercel without OWNER_ACCESS_CODE
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("OWNER_ACCESS_CODE", raising=False)
    status_resp = client.get("/api/access/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["upload_locked"] is True

    csv_data = b"a,b\n1,2\n"
    blocked = client.post(
        "/api/profile/upload",
        files={"file": ("secret.csv", io.BytesIO(csv_data), "text/csv")},
    )
    assert blocked.status_code == 403

    # Configure OWNER_ACCESS_CODE: wrong code -> 401, right code -> 200, sample -> 200
    monkeypatch.setenv("OWNER_ACCESS_CODE", "nusa-owner-2026")
    bad_code = client.post(
        "/api/profile/upload",
        files={"file": ("secret.csv", io.BytesIO(csv_data), "text/csv")},
        headers={"X-Owner-Code": "wrong"},
    )
    assert bad_code.status_code == 401

    sample_ok = client.post("/api/profile/sample/mini_orders")
    assert sample_ok.status_code == 200

    owner_ok = client.post(
        "/api/profile/upload",
        files={"file": ("secret.csv", io.BytesIO(csv_data), "text/csv")},
        headers={"X-Owner-Code": "nusa-owner-2026"},
    )
    assert owner_ok.status_code == 200

