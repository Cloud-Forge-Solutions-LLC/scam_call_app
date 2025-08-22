PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- Calls: one row per Twilio call SID
CREATE TABLE IF NOT EXISTS calls (
  call_sid         TEXT PRIMARY KEY,
  to_number        TEXT,
  from_number      TEXT,
  started_at       INTEGER,     -- epoch seconds
  completed_at     INTEGER,     -- epoch seconds
  duration_seconds INTEGER,
  voice            TEXT,
  dialog_idx       INTEGER,
  outcome          TEXT,        -- from legacy CSV if present
  prompt_used      TEXT,        -- from legacy CSV if present
  meta_json        TEXT,        -- optional JSON bag for extra fields
  created_at       INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- Transcript: one row per message/line in a call
CREATE TABLE IF NOT EXISTS transcript_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  call_sid   TEXT NOT NULL,
  seq        INTEGER NOT NULL,         -- 0..N ordering within a call
  role       TEXT NOT NULL CHECK (role IN ('Assistant','Callee')),
  text       TEXT NOT NULL,
  is_final   INTEGER NOT NULL DEFAULT 0,  -- 0 or 1
  event_ts   REAL,                      -- original event timestamp (seconds since epoch, may be fractional)
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  FOREIGN KEY (call_sid) REFERENCES calls(call_sid) ON DELETE CASCADE
);

-- Optional Twilio recordings linked to a call
CREATE TABLE IF NOT EXISTS recordings (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  call_sid       TEXT NOT NULL,
  recording_sid  TEXT NOT NULL UNIQUE,
  created_at     INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  FOREIGN KEY (call_sid) REFERENCES calls(call_sid) ON DELETE CASCADE
);

-- Helpful indexes for your API patterns
CREATE INDEX IF NOT EXISTS idx_calls_started_at ON calls(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_calls_completed_at ON calls(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_calls_duration ON calls(duration_seconds);
CREATE INDEX IF NOT EXISTS idx_transcript_by_call ON transcript_events(call_sid, seq);
CREATE INDEX IF NOT EXISTS idx_recordings_by_call ON recordings(call_sid);
