#!/usr/bin/env python3
"""
Bootstrap to run scam_call_app using SQLite for history storage and retrieval,
without modifying the existing large application file.

It monkey-patches:
- _persist_call_history
- _load_call_history
- _scan_history_summaries
- _compute_history_metrics

Run:
  python3 run_with_db.py

Optional:
  SCAM_APP_DB=/path/to/scam_app.db python3 run_with_db.py
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

# Import the main app module
import twilio_outbound_call as appmod  # type: ignore

# Initialize DB layer
from db import sqlite_store

sqlite_store.init(os.getenv("SCAM_APP_DB", os.path.abspath("./scam_app.db")))

# Local lock to serialize persist calls (complements app locks)
_PERSIST_LOCK = threading.RLock()


def _persist_call_history_db(sid: str) -> None:
    """
    Replacement for appmod._persist_call_history writing to SQLite.
    """
    if not sid:
        return

    # Snapshot in-memory meta and transcript
    with appmod._CALL_META_LOCK:
        meta = dict(appmod._CALL_META.get(sid, {}))
    with appmod._TRANSCRIPTS_LOCK:
        transcript = list(appmod._TRANSCRIPTS.get(sid, []))

    # Map meta to calls columns
    to_number = meta.get("to") or meta.get("to_number") or ""
    from_number = meta.get("from") or meta.get("from_number") or ""
    started_at = meta.get("started_at")
    completed_at = meta.get("completed_at")
    duration_seconds = meta.get("duration_seconds")
    voice = meta.get("voice")
    dialog_idx = meta.get("dialog_idx")
    outcome = meta.get("outcome")
    prompt_used = meta.get("prompt")

    # Derive completed_at if not present
    if completed_at is None and started_at is not None and duration_seconds is not None:
        try:
            completed_at = int(started_at) + int(duration_seconds)
        except Exception:
            completed_at = None

    # Serialize meta_json for forward compatibility
    meta_json = None
    try:
        meta_json = json.dumps(meta, ensure_ascii=False)
    except Exception:
        meta_json = None

    with _PERSIST_LOCK:
        # Upsert calls row
        sqlite_store.upsert_call(
            call_sid=sid,
            to_number=str(to_number) or None,
            from_number=str(from_number) or None,
            started_at=int(started_at) if isinstance(started_at, (int, float)) else None,
            completed_at=int(completed_at) if isinstance(completed_at, (int, float)) else None,
            duration_seconds=int(duration_seconds) if isinstance(duration_seconds, (int, float)) else None,
            voice=str(voice) if voice else None,
            dialog_idx=int(dialog_idx) if isinstance(dialog_idx, (int, float)) else None,
            outcome=str(outcome) if outcome else None,
            prompt_used=str(prompt_used) if prompt_used else None,
            meta_json=meta_json,
        )

        # Replace transcript rows
        items: List[Tuple[int, str, str, int, Optional[float]]] = []
        for i, e in enumerate(transcript):
            role = str(e.get("role") or "Assistant")
            text = str(e.get("text") or "")
            if not text:
                continue
            is_final = 1 if e.get("final") else 0
            t_val = e.get("t")
            try:
                event_ts = float(t_val) if t_val is not None else None
            except Exception:
                event_ts = None
            items.append((i, role, text, is_final, event_ts))
        sqlite_store.replace_transcript(sid, items)

        # Replace recordings
        recs = meta.get("recordings") or []
        rec_sids: List[str] = []
        for r in recs:
            if isinstance(r, dict):
                rec_sids.append(r.get("recording_sid") or r.get("recordingSid") or "")
            elif isinstance(r, str):
                rec_sids.append(r)
        sqlite_store.replace_recordings(sid, rec_sids)


def _load_call_history_db(sid: str) -> Optional[Dict[str, Any]]:
    """
    Replacement for appmod._load_call_history reading from SQLite and shaping
    the response exactly like the legacy JSON file.
    """
    return sqlite_store.get_call_detail(sid)


def _scan_history_summaries_db(limit: int = 200) -> List[Dict[str, Any]]:
    """
    Replacement for appmod._scan_history_summaries using SQLite.
    """
    return sqlite_store.get_history_summaries(limit=limit)


def _compute_history_metrics_db() -> Dict[str, Any]:
    """
    Replacement for appmod._compute_history_metrics using SQLite.
    """
    return sqlite_store.compute_metrics()


# Monkey-patch the app functions
appmod._persist_call_history = _persist_call_history_db
appmod._load_call_history = _load_call_history_db
appmod._scan_history_summaries = _scan_history_summaries_db
appmod._compute_history_metrics = _compute_history_metrics_db

if __name__ == "__main__":
    # Run the existing app entrypoint, now DB-backed for history.
    appmod.main()
