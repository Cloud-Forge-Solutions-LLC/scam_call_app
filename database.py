#!/usr/bin/env python3
"""
SQLite database utilities for scam call app.
Replaces filesystem JSON and CSV storage with a single SQLite database.
"""

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# Database configuration
DATABASE_PATH = Path("scam_app.db")


def init_database() -> None:
    """Initialize the SQLite database with required tables."""
    with get_db_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS call_history (
                call_sid TEXT PRIMARY KEY,
                started_at TEXT,  -- ISO format timestamp
                started_at_epoch INTEGER,  -- Unix timestamp for sorting
                completed_at INTEGER,  -- Unix timestamp
                duration_sec INTEGER DEFAULT 0,
                outcome TEXT,
                transcript TEXT,  -- JSON string
                prompt TEXT,
                to_number TEXT,
                from_number TEXT,
                has_recordings INTEGER DEFAULT 0,  -- boolean as int
                meta_json TEXT,  -- Full meta data as JSON
                created_at REAL DEFAULT (strftime('%s', 'now')),  -- Record creation time
                updated_at REAL DEFAULT (strftime('%s', 'now'))   -- Last update time
            );
            
            CREATE INDEX IF NOT EXISTS idx_call_history_started_at_epoch 
            ON call_history(started_at_epoch);
            
            CREATE INDEX IF NOT EXISTS idx_call_history_created_at 
            ON call_history(created_at);
        """)


@contextmanager
def get_db_connection():
    """Context manager for database connections with proper cleanup."""
    conn = sqlite3.connect(str(DATABASE_PATH))
    conn.row_factory = sqlite3.Row  # Enable dict-like access
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def persist_call_history_json(sid: str, meta: Dict[str, Any], transcript: List[Dict[str, Any]]) -> None:
    """
    Persist call history in the format used by twilio_outbound_call.py
    """
    if not sid:
        return
    
    # Extract common fields from meta
    started_at = meta.get("started_at")
    completed_at = meta.get("completed_at")
    duration_seconds = meta.get("duration_seconds", 0)
    to_number = meta.get("to", "")
    from_number = meta.get("from", "")
    has_recordings = bool(meta.get("recordings"))
    
    # Convert started_at to epoch if it's not already
    started_at_epoch = None
    if started_at is not None:
        try:
            started_at_epoch = int(started_at)
        except (ValueError, TypeError):
            started_at_epoch = None
    
    with get_db_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO call_history (
                call_sid, started_at, started_at_epoch, completed_at, duration_sec,
                outcome, transcript, to_number, from_number, has_recordings,
                meta_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sid,
            str(started_at) if started_at is not None else None,
            started_at_epoch,
            completed_at,
            duration_seconds or 0,
            "",  # outcome not used in twilio_outbound_call.py format
            json.dumps(transcript, ensure_ascii=False),
            to_number,
            from_number,
            int(has_recordings),
            json.dumps(meta, ensure_ascii=False),
            time.time()
        ))


def persist_call_history_csv(call_sid: str, started_at: str, duration_sec: int, 
                            outcome: str, transcript: str, prompt: str) -> None:
    """
    Persist call history in the format used by test.py (CSV format)
    """
    if not call_sid:
        return
    
    # Parse started_at to epoch for sorting
    started_at_epoch = None
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
        started_at_epoch = int(dt.timestamp())
    except Exception:
        started_at_epoch = int(time.time())
    
    with get_db_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO call_history (
                call_sid, started_at, started_at_epoch, duration_sec, outcome, 
                transcript, prompt, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            call_sid,
            started_at,
            started_at_epoch,
            duration_sec,
            outcome,
            transcript,
            prompt,
            time.time()
        ))


def load_call_history_json(sid: str) -> Optional[Dict[str, Any]]:
    """
    Load call history in the format expected by twilio_outbound_call.py
    Returns: {"sid": sid, "meta": {...}, "transcript": [...]} or None
    """
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM call_history WHERE call_sid = ?", (sid,)
        ).fetchone()
        
        if not row:
            return None
        
        # Reconstruct the meta dict
        meta = {}
        if row['meta_json']:
            try:
                meta = json.loads(row['meta_json'])
            except Exception:
                pass
        
        # Add basic fields to meta if not already present
        if row['started_at_epoch'] is not None:
            meta.setdefault('started_at', row['started_at_epoch'])
        if row['completed_at'] is not None:
            meta.setdefault('completed_at', row['completed_at'])
        if row['duration_sec'] is not None:
            meta.setdefault('duration_seconds', row['duration_sec'])
        if row['to_number']:
            meta.setdefault('to', row['to_number'])
        if row['from_number']:
            meta.setdefault('from', row['from_number'])
        if row['has_recordings']:
            meta.setdefault('recordings', True)
        
        # Parse transcript
        transcript = []
        if row['transcript']:
            try:
                transcript = json.loads(row['transcript'])
            except Exception:
                pass
        
        return {
            "sid": row['call_sid'],
            "meta": meta,
            "transcript": transcript
        }


def load_history_rows_csv() -> List[Dict[str, str]]:
    """
    Load call history in the format expected by test.py (CSV format)
    Returns list of dicts with keys: callSid, startedAt, durationSec, outcome, transcript, prompt
    """
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT call_sid, started_at, duration_sec, outcome, transcript, prompt 
            FROM call_history 
            ORDER BY started_at_epoch DESC, created_at DESC
        """).fetchall()
        
        result = []
        for row in rows:
            result.append({
                'callSid': row['call_sid'] or '',
                'startedAt': row['started_at'] or '',
                'durationSec': str(row['duration_sec'] or 0),
                'outcome': row['outcome'] or '',
                'transcript': row['transcript'] or '',
                'prompt': row['prompt'] or ''
            })
        
        return result


def scan_history_summaries(limit: int = 200) -> List[Dict[str, Any]]:
    """
    Load call history summaries in the format expected by twilio_outbound_call.py
    Returns list of dicts with keys: sid, started_at, completed_at, to, from, duration_seconds, has_recordings
    """
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT call_sid, started_at_epoch, completed_at, to_number, from_number, 
                   duration_sec, has_recordings
            FROM call_history 
            ORDER BY started_at_epoch DESC, created_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
        
        result = []
        for row in rows:
            result.append({
                'sid': row['call_sid'] or '',
                'started_at': row['started_at_epoch'],  # epoch seconds
                'completed_at': row['completed_at'],
                'to': row['to_number'] or '',
                'from': row['from_number'] or '',
                'duration_seconds': row['duration_sec'] or 0,
                'has_recordings': bool(row['has_recordings'])
            })
        
        return result


def compute_history_metrics() -> Dict[str, Any]:
    """
    Compute history metrics in the format expected by twilio_outbound_call.py
    """
    with get_db_connection() as conn:
        row = conn.execute("""
            SELECT 
                COUNT(*) as total_calls,
                SUM(COALESCE(duration_sec, 0)) as total_duration_seconds
            FROM call_history
        """).fetchone()
        
        total_calls = row['total_calls'] or 0
        total_duration = row['total_duration_seconds'] or 0
        average_duration = total_duration / total_calls if total_calls > 0 else 0
        
        return {
            "total_calls": total_calls,
            "total_duration_seconds": total_duration,
            "average_call_seconds": average_duration
        }


def migrate_existing_data() -> None:
    """
    Migrate existing data from CSV and JSON files to SQLite database.
    This should be called once during the transition.
    """
    import csv
    from pathlib import Path
    
    # Initialize database first
    init_database()
    
    # Migrate CSV data (from test.py format)
    csv_path = Path("data/call_history.csv")
    if csv_path.exists():
        print(f"Migrating CSV data from {csv_path}")
        try:
            with open(csv_path, 'r', encoding='utf-8', newline='') as f:
                reader = csv.DictReader(f)
                migrated_count = 0
                for row in reader:
                    call_sid = row.get('callSid', '').strip()
                    if call_sid:
                        persist_call_history_csv(
                            call_sid=call_sid,
                            started_at=row.get('startedAt', ''),
                            duration_sec=int(row.get('durationSec', '0') or '0'),
                            outcome=row.get('outcome', ''),
                            transcript=row.get('transcript', ''),
                            prompt=row.get('prompt', '')
                        )
                        migrated_count += 1
                print(f"Migrated {migrated_count} records from CSV")
        except Exception as e:
            print(f"Error migrating CSV data: {e}")
    
    # Migrate JSON data (from twilio_outbound_call.py format)
    json_dir = Path("data/history")
    if json_dir.exists():
        print(f"Migrating JSON data from {json_dir}")
        migrated_count = 0
        for json_file in json_dir.glob("*.json"):
            try:
                data = json.loads(json_file.read_text(encoding='utf-8'))
                sid = data.get('sid', '')
                meta = data.get('meta', {})
                transcript = data.get('transcript', [])
                
                if sid:
                    persist_call_history_json(sid, meta, transcript)
                    migrated_count += 1
            except Exception as e:
                print(f"Error migrating {json_file}: {e}")
        print(f"Migrated {migrated_count} records from JSON files")
    
    print("Data migration completed")


if __name__ == "__main__":
    # For testing/migration purposes
    migrate_existing_data()