#!/usr/bin/env python3
"""
Synchronize Twilio call history for specific phone numbers into the existing scam_app.db.

What this script does
- Reads calls from Twilio where To or From matches any of the provided numbers.
- Inserts/updates rows in your existing tables:
    - calls (one row per call SID)
    - recordings (one row per Twilio recording SID)
    - transcript_events (optional; created from any Twilio Recording Transcriptions found)
- Preserves your schema exactly as provided; it does not create or alter tables.
- Uses upserts for calls and recordings so re-running is safe.
- For transcript_events:
    - If a call already has transcript_events in your DB, the script leaves them untouched by default.
    - If a call has no transcript_events and Twilio has one or more Recording Transcriptions, the script inserts a single "Callee" line per transcription (is_final = 1), ordered by transcription create time.
      Note: Twilio transcriptions are not role-annotated; they are treated as caller/callee text for display purposes.

Requirements
- Environment:
    TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    TWILIO_AUTH_TOKEN=your_auth_token
- Python packages:
    pip install twilio

Usage examples
  # Default numbers (from your request) and default DB path ./scam_app.db
  python tools/sync_twilio_to_app_db.py

  # Custom date range (UTC; inclusive)
  python tools/sync_twilio_to_app_db.py --start 2025-08-01 --end 2025-08-15

  # Custom DB path and numbers, replace transcripts if Twilio has them
  python tools/sync_twilio_to_app_db.py \
      --db ./scam_app.db \
      --numbers +14806396734,+12093202395,+19162487450 \
      --replace-transcripts

Notes
- If you need event-granular conversational roles, consider generating/storing those during calls in your app.
- Historical calls that only have recordings (no Twilio transcription objects) will be imported without transcript_events.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sqlite3
import sys
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from twilio.rest import Client


# ---------------------------
# Configuration and CLI
# ---------------------------

DEFAULT_NUMBERS = "+14806396734,+12093202395,+19162487450"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sync Twilio calls, recordings, and any available transcriptions into scam_app.db."
    )
    p.add_argument(
        "--db",
        default="scam_app.db",
        help="Path to SQLite database (default: scam_app.db)",
    )
    p.add_argument(
        "--numbers",
        default=DEFAULT_NUMBERS,
        help="Comma-separated E.164 numbers to match against both To and From.",
    )
    p.add_argument(
        "--start",
        help="Start date (YYYY-MM-DD) inclusive in UTC for call start time filter.",
    )
    p.add_argument(
        "--end",
        help="End date (YYYY-MM-DD) inclusive in UTC for call start time filter.",
    )
    p.add_argument(
        "--page-size",
        type=int,
        default=1000,
        help="Twilio API page size (default: 1000).",
    )
    p.add_argument(
        "--replace-transcripts",
        action="store_true",
        help="If set, replace existing transcript_events for a call with Twilio transcription text when available.",
    )
    return p.parse_args()


# ---------------------------
# Utilities
# ---------------------------

def to_epoch_seconds(x: Optional[dt.datetime]) -> Optional[int]:
    if x is None:
        return None
    if x.tzinfo is None:
        # Assume UTC if naive
        x = x.replace(tzinfo=dt.timezone.utc)
    return int(x.timestamp())


def parse_date_utc(s: Optional[str]) -> Optional[dt.datetime]:
    if not s:
        return None
    # Interpret as 00:00:00 UTC on that date
    return dt.datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)


def normalize_numbers(csv_numbers: str) -> List[str]:
    return [n.strip() for n in (csv_numbers or "").split(",") if n.strip()]


def safe_get(obj, name: str, default=None):
    try:
        return getattr(obj, name, default)
    except Exception:
        return default


# ---------------------------
# Twilio fetch logic
# ---------------------------

def iter_calls_for_number(
    client: Client,
    number: str,
    start_after: Optional[dt.datetime],
    end_before: Optional[dt.datetime],
    page_size: int,
) -> Iterable:
    """Yield calls where 'to' equals number and calls where 'from' equals number."""
    common: Dict[str, object] = {}
    # The Twilio Python SDK expects to, from, start_time_after, start_time_before (not to_, from_)
    if start_after:
        common["start_time_after"] = start_after
    if end_before:
        common["start_time_before"] = end_before

    # Incoming to the number
    for c in client.calls.stream(page_size=page_size, to=number, **common):
        yield c

    # Outgoing from the number
    for c in client.calls.stream(page_size=page_size, from_=number, **common):
        yield c


def list_unique_calls(
    client: Client,
    numbers: Sequence[str],
    start_after: Optional[dt.datetime],
    end_before: Optional[dt.datetime],
    page_size: int,
) -> List:
    seen: set[str] = set()
    result: List = []
    for n in numbers:
        for c in iter_calls_for_number(client, n, start_after, end_before, page_size):
            if c.sid in seen:
                continue
            seen.add(c.sid)
            result.append(c)
    # Sort by start_time descending (None last)
    result.sort(
        key=lambda c: (safe_get(c, "start_time") or dt.datetime.fromtimestamp(0, tz=dt.timezone.utc)),
        reverse=True,
    )
    return result


def list_recordings_for_call(client: Client, call_sid: str) -> List:
    try:
        return list(client.calls(call_sid).recordings.stream(page_size=1000))
    except Exception:
        return []


def list_transcriptions_for_recording(client: Client, recording_sid: str) -> List:
    try:
        return list(client.recordings(recording_sid).transcriptions.stream(page_size=1000))
    except Exception:
        # Resource may be unavailable or not used
        return []


# ---------------------------
# Database helpers (existing schema)
# ---------------------------

REQUIRED_TABLES = {"calls", "transcript_events", "recordings"}

SQL_SELECT_TABLES = "SELECT name FROM sqlite_master WHERE type='table'"

SQL_UPSERT_CALL = """
INSERT INTO calls (
  call_sid, to_number, from_number, started_at, completed_at, duration_seconds,
  voice, dialog_idx, outcome, prompt_used, meta_json, created_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, strftime('%s','now')))
ON CONFLICT(call_sid) DO UPDATE SET
  to_number=excluded.to_number,
  from_number=excluded.from_number,
  started_at=excluded.started_at,
  completed_at=excluded.completed_at,
  duration_seconds=excluded.duration_seconds,
  voice=excluded.voice,
  dialog_idx=excluded.dialog_idx,
  outcome=excluded.outcome,
  prompt_used=excluded.prompt_used,
  meta_json=excluded.meta_json
"""

SQL_UPSERT_RECORDING = """
INSERT INTO recordings (call_sid, recording_sid)
VALUES (?, ?)
ON CONFLICT(recording_sid) DO UPDATE SET
  call_sid=excluded.call_sid
"""

SQL_COUNT_TRANSCRIPTS_FOR_CALL = "SELECT COUNT(1) FROM transcript_events WHERE call_sid = ?"

SQL_DELETE_TRANSCRIPTS_FOR_CALL = "DELETE FROM transcript_events WHERE call_sid = ?"

SQL_INSERT_TRANSCRIPT_EVENT = """
INSERT INTO transcript_events (call_sid, seq, role, text, is_final, event_ts)
VALUES (?, ?, ?, ?, ?, ?)
"""

def ensure_required_tables(con: sqlite3.Connection) -> None:
    cur = con.cursor()
    cur.execute(SQL_SELECT_TABLES)
    names = {row[0] for row in cur.fetchall()}
    missing = REQUIRED_TABLES - names
    if missing:
        raise RuntimeError(
            "Database is missing required tables: " + ", ".join(sorted(missing))
        )


# ---------------------------
# Persistence mapping
# ---------------------------

def build_meta_json(call) -> str:
    meta: Dict[str, object] = {
        "status": safe_get(call, "status"),
        "direction": safe_get(call, "direction"),
        "price": safe_get(call, "price"),
        "price_unit": safe_get(call, "price_unit"),
        "answered_by": safe_get(call, "answered_by"),
        "queue_time": safe_get(call, "queue_time"),
        "uri": safe_get(call, "uri"),
        "parent_call_sid": safe_get(call, "parent_call_sid"),
        "caller_name": safe_get(call, "caller_name"),
        "account_sid": safe_get(call, "account_sid"),
    }
    # Remove None values for compact storage
    meta_clean = {k: v for k, v in meta.items() if v is not None and v != ""}
    return json.dumps(meta_clean, separators=(",", ":"), ensure_ascii=False)


def upsert_call(con: sqlite3.Connection, call) -> None:
    cur = con.cursor()
    started_at = to_epoch_seconds(safe_get(call, "start_time"))
    completed_at = to_epoch_seconds(safe_get(call, "end_time"))
    duration = safe_get(call, "duration")
    duration_i = int(duration) if duration not in (None, "") else None

    # Your schema includes voice and dialog_idx, which Twilio does not provide.
    voice = None
    dialog_idx = None

    # outcome and prompt_used are legacy CSV fields; leave as NULL.
    outcome = None
    prompt_used = None

    meta_json = build_meta_json(call)

    cur.execute(
        SQL_UPSERT_CALL,
        (
            call.sid,
            safe_get(call, "to"),
            safe_get(call, "from_") if hasattr(call, "from_") else safe_get(call, "from"),
            started_at,
            completed_at,
            duration_i,
            voice,
            dialog_idx,
            outcome,
            prompt_used,
            meta_json,
            None,  # created_at (preserve existing default if row is new)
        ),
    )


def upsert_recording(con: sqlite3.Connection, call_sid: str, recording_sid: str) -> None:
    cur = con.cursor()
    cur.execute(SQL_UPSERT_RECORDING, (call_sid, recording_sid))


def transcripts_exist_for_call(con: sqlite3.Connection, call_sid: str) -> bool:
    cur = con.cursor()
    cur.execute(SQL_COUNT_TRANSCRIPTS_FOR_CALL, (call_sid,))
    n = cur.fetchone()[0]
    return n > 0


def replace_transcripts_for_call(
    con: sqlite3.Connection,
    call_sid: str,
    transcription_items: List,
) -> int:
    """
    Replace transcript_events for the call with one line per Twilio Transcription (role='Callee', is_final=1).
    Returns number of events inserted.
    """
    cur = con.cursor()
    cur.execute(SQL_DELETE_TRANSCRIPTS_FOR_CALL, (call_sid,))

    # Order by date_created if available to maintain chronology
    def _key(t):
        dc = safe_get(t, "date_created")
        if dc is None:
            return dt.datetime.fromtimestamp(0, tz=dt.timezone.utc)
        if isinstance(dc, dt.datetime):
            return dc
        # Fallback if Twilio returns string
        try:
            return dt.datetime.fromisoformat(str(dc))
        except Exception:
            return dt.datetime.fromtimestamp(0, tz=dt.timezone.utc)

    sorted_tr = sorted(transcription_items, key=_key)

    seq = 0
    inserted = 0
    for t in sorted_tr:
        text = safe_get(t, "transcription_text")
        if not text:
            continue
        # Treat each Twilio transcription as a single final "Callee" line
        event_ts = to_epoch_seconds(safe_get(t, "date_created"))
        cur.execute(
            SQL_INSERT_TRANSCRIPT_EVENT,
            (call_sid, seq, "Callee", text, 1, float(event_ts) if event_ts is not None else None),
        )
        seq += 1
        inserted += 1

    return inserted


# ---------------------------
# Main synchronization
# ---------------------------

def main() -> int:
    account_sid = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
    auth_token = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
    if not account_sid or not auth_token:
        print("Missing TWILIO_ACCOUNT_SID or TWILIO_AUTH_TOKEN environment variables.", file=sys.stderr)
        return 2

    args = parse_args()
    numbers = normalize_numbers(args.numbers)
    if not numbers:
        print("No phone numbers provided to filter on.", file=sys.stderr)
        return 2

    start_after = parse_date_utc(args.start)
    end_before = None
    if args.end:
        end_d = parse_date_utc(args.end)
        if end_d:
            end_before = end_d + dt.timedelta(days=1)

    # Initialize clients
    client = Client(account_sid, auth_token)

    # Database
    con = sqlite3.connect(args.db)
    con.execute("PRAGMA foreign_keys = ON;")
    try:
        ensure_required_tables(con)
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        con.close()
        return 2

    print(f"Fetching calls for numbers: {', '.join(numbers)}", file=sys.stderr)
    calls = list_unique_calls(client, numbers, start_after, end_before, args.page_size)
    print(f"Found {len(calls)} call(s).", file=sys.stderr)

    total_recordings = 0
    total_transcript_calls = 0
    total_transcript_events = 0

    try:
        for idx, call in enumerate(calls, start=1):
            upsert_call(con, call)

            # Recordings
            recs = list_recordings_for_call(client, call.sid)
            for rec in recs:
                rec_sid = safe_get(rec, "sid")
                if rec_sid:
                    upsert_recording(con, call.sid, rec_sid)
                    total_recordings += 1

            # Transcripts: only if none exist already, unless --replace-transcripts is set
            should_replace = args.replace_transcripts or not transcripts_exist_for_call(con, call.sid)
            if should_replace:
                # Gather all Twilio transcriptions attached to any recording for this call
                tr_items: List = []
                for rec in recs:
                    rec_sid = safe_get(rec, "sid")
                    if not rec_sid:
                        continue
                    tr_items.extend(list_transcriptions_for_recording(client, rec_sid))
                if tr_items:
                    inserted = replace_transcripts_for_call(con, call.sid, tr_items)
                    if inserted > 0:
                        total_transcript_calls += 1
                        total_transcript_events += inserted

            # Commit periodically
            if (idx % 50) == 0:
                con.commit()
                print(f"Progress: {idx}/{len(calls)} calls processed...", file=sys.stderr)

        con.commit()
    finally:
        con.close()

    print(
        (
            "Done. Calls: {calls}, Recordings: {recs}, "
            "Calls with transcripts inserted/replaced: {tcalls}, Transcript events inserted: {tevents}."
        ).format(calls=len(calls), recs=total_recordings, tcalls=total_transcript_calls, tevents=total_transcript_events),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
