#!/usr/bin/env python3
"""
Migrate local history into SQLite:
- Imports data/history/*.json into calls, transcript_events, and recordings.
- Imports app/data/call_history.csv into calls and, when possible, transcript_events.

Usage:
  python3 scripts/migrate_to_sqlite.py --db ./scam_app.db \
      --json-dir ./data/history --csv ./app/data/call_history.csv

Notes:
- Existing rows in calls are preserved; missing fields will be filled.
- transcript_events and recordings for a call are replaced when importing from JSON.
- CSV transcript expansion runs only if a call has no transcript events yet.
"""

import argparse
import csv
import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

def parse_epoch(value: Any) -> Optional[int]:
    """Parse various representations into epoch seconds (int)."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except Exception:
            return None
    s = str(value).strip()
    if not s:
        return None
    # Numeric string
    try:
        return int(float(s))
    except Exception:
        pass
    # ISO-8601 attempt
    try:
        # Normalize trailing Z
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        # Allow space separator
        s = s.replace(" ", "T") if "T" not in s and "-" in s else s
        dt = datetime.fromisoformat(s)
        return int(dt.timestamp())
    except Exception:
        return None

def compute_completed(started_at: Optional[int], duration_seconds: Optional[int]) -> Optional[int]:
    if started_at is None or duration_seconds is None:
        return None
    try:
        return int(started_at) + int(duration_seconds)
    except Exception:
        return None

def normalize_role(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    s = str(raw).strip().lower()
    if s in ("assistant",):
        return "Assistant"
    if s in ("callee", "caller", "user", "customer"):
        return "Callee"
    return None

def parse_csv_transcript_field(raw: str) -> List[Tuple[str, str]]:
    """
    Attempt to parse CSV transcript field.
    Accepts:
      - JSON list of strings like "Assistant: Hello", "Callee: Hi"
      - JSON list of objects with keys {role, text}
      - Plain string (falls back to a single Assistant line)
    Returns list of (role, text)
    """
    if raw is None:
        return []
    raw = str(raw).strip()
    if not raw:
        return []
    # Try JSON
    try:
        data = json.loads(raw)
        out: List[Tuple[str, str]] = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    # Split "Assistant: ..." or "Callee: ..."
                    m = re.match(r"^\s*(Assistant|Callee)\s*:\s*(.*)$", item.strip())
                    if m:
                        out.append((m.group(1), m.group(2)))
                    else:
                        # Unknown, assume Assistant
                        out.append(("Assistant", item.strip()))
                elif isinstance(item, dict):
                    role = normalize_role(item.get("role")) or "Assistant"
                    text = str(item.get("text") or "").strip()
                    if text:
                        out.append((role, text))
        elif isinstance(data, str):
            # Single line
            m = re.match(r"^\s*(Assistant|Callee)\s*:\s*(.*)$", data.strip())
            if m:
                return [(m.group(1), m.group(2))]
            return [("Assistant", data.strip())]
        return out
    except Exception:
        # Not JSON; treat as single line
        m = re.match(r"^\s*(Assistant|Callee)\s*:\s*(.*)$", raw)
        if m:
            return [(m.group(1), m.group(2))]
        return [("Assistant", raw)]

def ensure_connection(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def call_exists(conn: sqlite3.Connection, call_sid: str) -> bool:
    cur = conn.execute("SELECT 1 FROM calls WHERE call_sid = ? LIMIT 1", (call_sid,))
    return cur.fetchone() is not None

def upsert_call(conn: sqlite3.Connection, row: Dict[str, Any]) -> None:
    """
    Insert a call row if missing; otherwise fill any NULL columns with provided values.
    """
    cols = [
        "call_sid", "to_number", "from_number", "started_at", "completed_at",
        "duration_seconds", "voice", "dialog_idx", "outcome", "prompt_used", "meta_json"
    ]
    insert_sql = f"""
        INSERT INTO calls ({", ".join(cols)})
        VALUES ({", ".join([":" + c for c in cols])})
    """
    update_sql = """
        UPDATE calls SET
          to_number        = COALESCE(to_number,        :to_number),
          from_number      = COALESCE(from_number,      :from_number),
          started_at       = COALESCE(started_at,       :started_at),
          completed_at     = COALESCE(completed_at,     :completed_at),
          duration_seconds = COALESCE(duration_seconds, :duration_seconds),
          voice            = COALESCE(voice,            :voice),
          dialog_idx       = COALESCE(dialog_idx,       :dialog_idx),
          outcome          = COALESCE(outcome,          :outcome),
          prompt_used      = COALESCE(prompt_used,      :prompt_used),
          meta_json        = COALESCE(meta_json,        :meta_json)
        WHERE call_sid = :call_sid
    """
    try:
        conn.execute(insert_sql, row)
    except sqlite3.IntegrityError:
        conn.execute(update_sql, row)

def clear_transcript(conn: sqlite3.Connection, call_sid: str) -> None:
    conn.execute("DELETE FROM transcript_events WHERE call_sid = ?", (call_sid,))

def clear_recordings(conn: sqlite3.Connection, call_sid: str) -> None:
    conn.execute("DELETE FROM recordings WHERE call_sid = ?", (call_sid,))

def transcript_count(conn: sqlite3.Connection, call_sid: str) -> int:
    cur = conn.execute("SELECT COUNT(1) FROM transcript_events WHERE call_sid = ?", (call_sid,))
    row = cur.fetchone()
    return int(row[0]) if row and row[0] is not None else 0

def insert_transcript_events(conn: sqlite3.Connection, call_sid: str, items: List[Dict[str, Any]]) -> None:
    """
    items: list of dict with keys: seq, role, text, is_final, event_ts
    """
    sql = """
        INSERT INTO transcript_events (call_sid, seq, role, text, is_final, event_ts)
        VALUES (:call_sid, :seq, :role, :text, :is_final, :event_ts)
    """
    conn.executemany(sql, [
        {
            "call_sid": call_sid,
            "seq": int(it.get("seq", i)),
            "role": str(it.get("role") or "Assistant"),
            "text": str(it.get("text") or ""),
            "is_final": 1 if it.get("is_final") else 0,
            "event_ts": it.get("event_ts"),
        }
        for i, it in enumerate(items)
        if str(it.get("text") or "").strip()
    ])

def insert_recordings(conn: sqlite3.Connection, call_sid: str, recording_sids: Iterable[str]) -> None:
    sql = """
        INSERT OR IGNORE INTO recordings (call_sid, recording_sid) VALUES (?, ?)
    """
    conn.executemany(sql, [(call_sid, rsid) for rsid in recording_sids if rsid])

def import_json_history(conn: sqlite3.Connection, json_dir: Path) -> Tuple[int, int]:
    """
    Import JSON history files (data/history/*.json).
    Returns: (calls_imported_or_updated, events_inserted)
    """
    if not json_dir.exists():
        return (0, 0)

    call_rows = 0
    event_rows = 0

    for f in sorted(json_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[WARN] Failed to read {f}: {e}")
            continue

        sid = (data.get("sid") or "").strip()
        if not sid:
            print(f"[WARN] Missing sid in {f}")
            continue

        meta = data.get("meta") or {}
        tx = data.get("transcript") or []

        started_at = parse_epoch(meta.get("started_at"))
        completed_at = parse_epoch(meta.get("completed_at"))
        duration_seconds = None
        try:
            if meta.get("duration_seconds") is not None:
                duration_seconds = int(float(meta.get("duration_seconds")))
        except Exception:
            duration_seconds = None
        if duration_seconds is None and started_at is not None and completed_at is not None:
            duration_seconds = max(0, completed_at - started_at)

        row = {
            "call_sid": sid,
            "to_number": (meta.get("to") or None),
            "from_number": (meta.get("from") or None),
            "started_at": started_at,
            "completed_at": completed_at if completed_at is not None else compute_completed(started_at, duration_seconds),
            "duration_seconds": duration_seconds,
            "voice": (meta.get("voice") or None),
            "dialog_idx": meta.get("dialog_idx"),
            "outcome": meta.get("outcome") or None,
            "prompt_used": meta.get("prompt") or None,
            "meta_json": json.dumps(meta, ensure_ascii=False) if meta else None,
        }

        upsert_call(conn, row)
        call_rows += 1

        # Replace transcript for this call based on JSON truth
        clear_transcript(conn, sid)
        items: List[Dict[str, Any]] = []
        for i, e in enumerate(tx):
            if not isinstance(e, dict):
                # Allow legacy "Assistant: ..." string lines (rare in JSON)
                s = str(e).strip()
                if not s:
                    continue
                m = re.match(r"^\s*(Assistant|Callee)\s*:\s*(.*)$", s)
                if m:
                    items.append({
                        "seq": i,
                        "role": m.group(1),
                        "text": m.group(2),
                        "is_final": 1,
                        "event_ts": None,
                    })
                else:
                    items.append({
                        "seq": i,
                        "role": "Assistant",
                        "text": s,
                        "is_final": 1,
                        "event_ts": None,
                    })
                continue

            role = normalize_role(e.get("role")) or "Assistant"
            text = str(e.get("text") or "").strip()
            if not text:
                continue
            is_final = bool(e.get("final"))
            t = e.get("t")
            event_ts = None
            try:
                if t is not None:
                    event_ts = float(t)
            except Exception:
                event_ts = None
            items.append({
                "seq": i,
                "role": role,
                "text": text,
                "is_final": 1 if is_final else 0,
                "event_ts": event_ts,
            })
        insert_transcript_events(conn, sid, items)
        event_rows += len(items)

        # Replace recordings based on JSON meta
        clear_recordings(conn, sid)
        recs = meta.get("recordings") or []
        sids: List[str] = []
        for r in recs:
            if isinstance(r, dict):
                sids.append(r.get("recording_sid") or r.get("recordingSid") or "")
            elif isinstance(r, str):
                sids.append(r)
        insert_recordings(conn, sid, sids)

    return (call_rows, event_rows)

def import_csv_history(conn: sqlite3.Connection, csv_path: Path) -> Tuple[int, int]:
    """
    Import CSV history (app/data/call_history.csv) into calls and, if missing, transcript_events.
    Returns: (calls_imported_or_updated, events_inserted)
    """
    if not csv_path.exists():
        return (0, 0)

    call_rows = 0
    event_rows = 0

    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            sid = (r.get("callSid") or r.get("call_sid") or "").strip()
            if not sid:
                continue

            started_at = parse_epoch(r.get("startedAt") or r.get("started_at"))
            duration_seconds = None
            try:
                val = r.get("durationSec") or r.get("duration_sec") or r.get("duration")
                if val is not None and str(val).strip() != "":
                    duration_seconds = int(float(val))
            except Exception:
                duration_seconds = None

            completed_at = parse_epoch(r.get("completedAt") or r.get("completed_at"))
            if completed_at is None:
                computed = compute_completed(started_at, duration_seconds)
                if computed is not None:
                    completed_at = computed

            to_number = (r.get("to") or "").strip() or None
            from_number = (r.get("from") or "").strip() or None

            row = {
                "call_sid": sid,
                "to_number": to_number,
                "from_number": from_number,
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_seconds": duration_seconds,
                "voice": None,
                "dialog_idx": None,
                "outcome": (r.get("outcome") or "").strip() or None,
                "prompt_used": (r.get("prompt") or "").strip() or None,
                "meta_json": None,
            }
            upsert_call(conn, row)
            call_rows += 1

            # Only expand CSV transcript if the call has no events yet
            if transcript_count(conn, sid) == 0:
                raw_tx = r.get("transcript") or ""
                pairs = parse_csv_transcript_field(raw_tx)
                if pairs:
                    items = [
                        {"seq": i, "role": role, "text": text, "is_final": 1, "event_ts": None}
                        for i, (role, text) in enumerate(pairs)
                        if str(text).strip()
                    ]
                    insert_transcript_events(conn, sid, items)
                    event_rows += len(items)

    return (call_rows, event_rows)

def main():
    ap = argparse.ArgumentParser(description="Migrate local call history into SQLite.")
    ap.add_argument("--db", required=True, help="Path to SQLite DB file (e.g., ./scam_app.db)")
    ap.add_argument("--json-dir", default="./data/history", help="Directory containing JSON history files")
    ap.add_argument("--csv", default="./app/data/call_history.csv", help="Path to legacy CSV file")
    args = ap.parse_args()

    db_path = Path(args.db).resolve()
    json_dir = Path(args.json_dir).resolve()
    csv_path = Path(args.csv).resolve()

    if not db_path.exists():
        print(f"[INFO] Database does not exist yet: {db_path}")
        print("       Create it first with schema.sql: sqlite3 ./scam_app.db < scripts/schema.sql")

    conn = ensure_connection(db_path)
    try:
        conn.execute("SELECT 1 FROM calls LIMIT 1")
    except Exception:
        print("[WARN] Schema not found. Please initialize schema first:\n       sqlite3 ./scam_app.db < scripts/schema.sql")
        conn.close()
        return

    total_calls = 0
    total_events = 0

    print(f"[INFO] Importing JSON history from: {json_dir}")
    c_json, e_json = import_json_history(conn, json_dir)
    conn.commit()
    total_calls += c_json
    total_events += e_json
    print(f"[INFO] JSON import: calls upserted={c_json}, transcript events inserted={e_json}")

    print(f"[INFO] Importing CSV history from: {csv_path}")
    c_csv, e_csv = import_csv_history(conn, csv_path)
    conn.commit()
    total_calls += c_csv
    total_events += e_csv
    print(f"[INFO] CSV import: calls upserted={c_csv}, transcript events inserted={e_csv}")

    print(f"[OK] Migration complete. Total calls touched={total_calls}, transcript events inserted={total_events}")
    conn.close()

if __name__ == "__main__":
    main()
