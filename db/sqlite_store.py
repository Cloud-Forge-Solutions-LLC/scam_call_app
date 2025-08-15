#!/usr/bin/env python3
"""
SQLite data layer for scam_call_app.

Tables expected (see scripts/schema.sql):
- calls(call_sid PK, to_number, from_number, started_at, completed_at, duration_seconds,
        voice, dialog_idx, outcome, prompt_used, meta_json, created_at)
- transcript_events(id PK, call_sid FK, seq, role, text, is_final, event_ts, created_at)
- recordings(id PK, call_sid FK, recording_sid UNIQUE, created_at)

Environment:
- SCAM_APP_DB: optional path to DB file (default: ./scam_app.db)
"""

from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

_DEFAULT_DB = os.getenv("SCAM_APP_DB", os.path.abspath("./scam_app.db"))

# Single connection guarded by a lock. SQLite is fine with this pattern for low QPS.
_CONN: Optional[sqlite3.Connection] = None
_LOCK = threading.RLock()


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Pragmas for integrity and performance
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def init(db_path: str = _DEFAULT_DB) -> None:
    global _CONN
    with _LOCK:
        if _CONN is None:
            _CONN = _connect(db_path)


def _ensure_conn() -> sqlite3.Connection:
    if _CONN is None:
        init(_DEFAULT_DB)
    assert _CONN is not None
    return _CONN


def upsert_call(
    call_sid: str,
    to_number: Optional[str],
    from_number: Optional[str],
    started_at: Optional[int],
    completed_at: Optional[int],
    duration_seconds: Optional[int],
    voice: Optional[str],
    dialog_idx: Optional[int],
    outcome: Optional[str],
    prompt_used: Optional[str],
    meta_json: Optional[str],
) -> None:
    """
    Insert or update (filling NULLs only) the calls row.
    """
    sql_insert = """
    INSERT INTO calls (
      call_sid, to_number, from_number, started_at, completed_at, duration_seconds,
      voice, dialog_idx, outcome, prompt_used, meta_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    sql_update = """
    UPDATE calls SET
      to_number        = COALESCE(to_number,        ?),
      from_number      = COALESCE(from_number,      ?),
      started_at       = COALESCE(started_at,       ?),
      completed_at     = COALESCE(completed_at,     ?),
      duration_seconds = COALESCE(duration_seconds, ?),
      voice            = COALESCE(voice,            ?),
      dialog_idx       = COALESCE(dialog_idx,       ?),
      outcome          = COALESCE(outcome,          ?),
      prompt_used      = COALESCE(prompt_used,      ?),
      meta_json        = COALESCE(meta_json,        ?)
    WHERE call_sid = ?
    """
    conn = _ensure_conn()
    with _LOCK, conn:
        try:
            conn.execute(
                sql_insert,
                (
                    call_sid,
                    to_number,
                    from_number,
                    started_at,
                    completed_at,
                    duration_seconds,
                    voice,
                    dialog_idx,
                    outcome,
                    prompt_used,
                    meta_json,
                ),
            )
        except sqlite3.IntegrityError:
            conn.execute(
                sql_update,
                (
                    to_number,
                    from_number,
                    started_at,
                    completed_at,
                    duration_seconds,
                    voice,
                    dialog_idx,
                    outcome,
                    prompt_used,
                    meta_json,
                    call_sid,
                ),
            )


def replace_transcript(call_sid: str, events: Sequence[Tuple[int, str, str, int, Optional[float]]]) -> None:
    """
    Replace all transcript events for a call.

    events: iterable of (seq, role, text, is_final_int, event_ts_float_or_None)
    """
    conn = _ensure_conn()
    with _LOCK, conn:
        conn.execute("DELETE FROM transcript_events WHERE call_sid = ?", (call_sid,))
        conn.executemany(
            """
            INSERT INTO transcript_events (call_sid, seq, role, text, is_final, event_ts)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [(call_sid, seq, role, text, is_final, event_ts) for (seq, role, text, is_final, event_ts) in events],
        )


def replace_recordings(call_sid: str, recording_sids: Sequence[str]) -> None:
    """
    Replace recordings list for a call.
    """
    conn = _ensure_conn()
    with _LOCK, conn:
        conn.execute("DELETE FROM recordings WHERE call_sid = ?", (call_sid,))
        conn.executemany(
            "INSERT OR IGNORE INTO recordings (call_sid, recording_sid) VALUES (?, ?)",
            [(call_sid, rsid) for rsid in recording_sids if rsid],
        )


def get_history_summaries(limit: int = 200) -> List[Dict[str, Any]]:
    """
    Return the list of call summaries ordered by started_at DESC, then created_at DESC.
    Output keys match the existing /api/history consumer:
      sid, started_at, completed_at, to, from, duration_seconds, has_recordings
    """
    conn = _ensure_conn()
    with _LOCK:
        cur = conn.execute(
            """
            SELECT
              c.call_sid AS sid,
              c.started_at,
              c.completed_at,
              c.to_number AS "to",
              c.from_number AS "from",
              COALESCE(c.duration_seconds, 0) AS duration_seconds,
              EXISTS(SELECT 1 FROM recordings r WHERE r.call_sid = c.call_sid) AS has_recordings
            FROM calls c
            ORDER BY COALESCE(c.started_at, 0) DESC, c.created_at DESC
            LIMIT ?
            """,
            (int(limit),),
        )
        return [dict(row) for row in cur.fetchall()]


def get_call_detail(sid: str) -> Optional[Dict[str, Any]]:
    """
    Return a structure shaped like the legacy JSON file:
    {
      "sid": "<sid>",
      "meta": { "to":..., "from":..., "started_at":..., "completed_at":..., "voice":..., "dialog_idx":..., "recordings":[{"recording_sid": "..."}] },
      "transcript": [ {"t": float|null, "role": "Assistant"|"Callee", "text": str, "final": bool}, ... ]
    }
    """
    conn = _ensure_conn()
    with _LOCK:
        c = conn.execute(
            """
            SELECT call_sid, to_number, from_number, started_at, completed_at, duration_seconds, voice, dialog_idx
            FROM calls WHERE call_sid = ? LIMIT 1
            """,
            (sid,),
        ).fetchone()
        if not c:
            return None

        recs = conn.execute(
            "SELECT recording_sid FROM recordings WHERE call_sid = ? ORDER BY id ASC",
            (sid,),
        ).fetchall()

        tx = conn.execute(
            """
            SELECT seq, role, text, is_final, event_ts
            FROM transcript_events
            WHERE call_sid = ?
            ORDER BY seq ASC, id ASC
            """,
            (sid,),
        ).fetchall()

    meta = {
        "to": c["to_number"] or "",
        "from": c["from_number"] or "",
        "started_at": c["started_at"],
        "completed_at": c["completed_at"],
        "duration_seconds": c["duration_seconds"],
        "voice": c["voice"] or "",
        "dialog_idx": c["dialog_idx"],
        "recordings": [{"recording_sid": r["recording_sid"]} for r in recs],
    }
    transcript = []
    for row in tx:
        transcript.append(
            {
                "t": float(row["event_ts"]) if row["event_ts"] is not None else None,
                "role": row["role"],
                "text": row["text"],
                "final": bool(row["is_final"]),
            }
        )

    return {"sid": c["call_sid"], "meta": meta, "transcript": transcript}


def compute_metrics() -> Dict[str, int]:
    """
    Compute { total_calls, total_duration_seconds, average_call_seconds }
    """
    conn = _ensure_conn()
    with _LOCK:
        tc = conn.execute("SELECT COUNT(1) AS n FROM calls").fetchone()["n"]
        tot = conn.execute(
            "SELECT COALESCE(SUM(COALESCE(duration_seconds,0)), 0) AS s FROM calls"
        ).fetchone()["s"]

    total_calls = int(tc or 0)
    total_duration_seconds = int(tot or 0)
    avg = int(total_duration_seconds / total_calls) if total_calls else 0
    return {
        "total_calls": total_calls,
        "total_duration_seconds": total_duration_seconds,
        "average_call_seconds": avg,
    }
