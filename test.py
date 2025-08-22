# -*- coding: utf-8 -*-
"""
Single-file Twilio outbound-caller Flask application with:
- Two-sided live audio streaming from the start of the call (Twilio Media Streams) and browser playback with separate gain controls.
- Robust transcription with partial buffering (500–600 ms) and end-of-call flush.
- Configurable rotating prompts and a “Modify Script” one-shot opener.
- Sanitization of assistant speech to avoid banned phrases.
- CSV/JSON export of call history.
- Admin login with .env editor and graceful hot-restart.
- Minimal external files; templates, CSS, and JS are embedded to keep the project in a single file.

Security, legal, and data handling:
- Treat any previously exposed credentials as compromised. Rotate immediately. Do not commit secrets.
- Store all credentials in a local .env file, which this app loads at runtime. The file is not created here.
- Default recording is OFF. Ensure you comply with applicable laws in your jurisdiction(s).
- Banned phrases (never spoken by the app):
    - “This is an automated assistant from Import Engines”
    - “Consent” (any casing)
- PII handling: avoid logging destination numbers except potentially last-4 when masking is enabled. Do not include PII in client logs.

Dependencies (install via pip):
  flask, flask-sock, simple-websocket, twilio, python-dotenv, bcrypt, itsdangerous, watchdog

Run:
  1) Create and populate a .env next to this file (see ENVIRONMENT VARIABLES section below).
  2) python twilio_outbound_app.py
  3) Expose a public HTTPS URL (e.g., via reverse proxy). Set PUBLIC_BASE_URL to that URL so Twilio can reach /voice and media sockets.
"""

import base64
import csv
import datetime as dt
import hashlib
import io
import json
import os
import random
import re
import signal
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Add vendor directory to path for dependencies
sys.path.insert(0, str(Path(__file__).parent / "vendor"))

from database import (
    init_database,
    persist_call_history_csv,
    load_history_rows_csv,
)

# Optional imports - make them optional for testing
try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = lambda: None

try:
    import bcrypt
except ImportError:
    bcrypt = None

try:
    from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
except ImportError:
    URLSafeTimedSerializer = BadSignature = SignatureExpired = None

# Essential Flask imports from vendor
from flask import (
    Flask,
    abort,
    jsonify,
    make_response,
    redirect,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)

try:
    from flask_sock import Sock
except ImportError:
    Sock = None

# Optional Twilio imports
try:
    from twilio.twiml.voice_response import VoiceResponse, Gather, Start, Stream, Pause, Say
    from twilio.rest import Client as TwilioClient
except ImportError:
    VoiceResponse = Gather = Start = Stream = Pause = Say = TwilioClient = None

# Optional watchdog imports
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    Observer = FileSystemEventHandler = None

# -------------------------
# ENVIRONMENT VARIABLES
# -------------------------
# Required/important:
# - TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN
# - FROM_NUMBER or FROM_NUMBERS (CSV, E.164)
# - TO_NUMBER (E.164)
# - PUBLIC_BASE_URL (e.g., https://your.domain)
# - RECORDING_MODE (off|mono|dual|ask) default off
# - RECORDING_JURISDICTION_MODE (disable_in_two_party|always|manual) default disable_in_two_party
# - COMPANY_NAME, TOPIC (strings)
# - TTS_VOICE (e.g., man|woman), TTS_LANGUAGE (e.g., en-US)
# - ROTATE_PROMPTS (true|false), ROTATE_PROMPTS_STRATEGY (sequential|random)
# - CALLEE_SILENCE_HANGUP_SECONDS (5-60), default 8
# - HISTORY_CSV_PATH (default ./data/call_history.csv)
# - ADMIN_USER, ADMIN_PASSWORD_HASH (bcrypt hash string)
# - ALLOWED_COUNTRY_CODES (CSV, default +1)
# - SECRET_KEY (Flask session secret), generate if missing
# - NONINTERACTIVE (true|false)
# - LOG_COLOR (1|0)
# - MIRROR_TRANSCRIPTS_DIR (path or empty)
#
# Optional:
# - ACTIVE_HOURS_LOCAL (e.g., 09:00-18:00), ACTIVE_DAYS (Mon,Tue,Wed,Thu,Fri)
# - MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS, HOURLY_MAX_ATTEMPTS_PER_DEST, DAILY_MAX_ATTEMPTS_PER_DEST
# - BACKOFF_STRATEGY (none|linear|exponential)
# - USE_NGROK/NGROK_AUTHTOKEN (not enabled here; prefer PUBLIC_BASE_URL)
# - AMD_* (not fully implemented in this single-file version)

load_dotenv()

# -------------------------
# Configuration and helpers
# -------------------------

E164_RE = re.compile(r"^\+\d{7,15}$")
TRUE_SET = {"1", "true", "yes", "on", "y", "t"}
FALSE_SET = {"0", "false", "no", "off", "n", "f"}

def env_str(key: str, default: str = "") -> str:
    return os.getenv(key, default).strip()

def env_bool(key: str, default: bool = False) -> bool:
    raw = os.getenv(key, "").strip().lower()
    if not raw:
        return default
    if raw in TRUE_SET:
        return True
    if raw in FALSE_SET:
        return False
    return default

def env_int(key: str, default: int) -> int:
    raw = os.getenv(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default

def parse_csv_env(key: str, default: List[str]) -> List[str]:
    raw = os.getenv(key, "").strip()
    if not raw:
        return list(default)
    return [x.strip() for x in raw.split(",") if x.strip()]

def validate_e164(number: str) -> bool:
    return bool(E164_RE.match(number))

def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def utc_iso(ts: Optional[dt.datetime] = None) -> str:
    return (ts or now_utc()).isoformat()

def ensure_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

def color(s: str, c: str) -> str:
    if env_bool("LOG_COLOR", False):
        return f"{c}{s}\033[0m"
    return s

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"

# -------------------------
# Global app and state
# -------------------------

app = Flask(__name__)
_sock = Sock(app)

SECRET_KEY = env_str("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    print(color("Generated ephemeral SECRET_KEY (set SECRET_KEY in .env for persistence).", YELLOW))
app.secret_key = SECRET_KEY

PUBLIC_BASE_URL = env_str("PUBLIC_BASE_URL")
if not PUBLIC_BASE_URL:
    print(color("PUBLIC_BASE_URL is required so Twilio can reach your app. Set it in .env.", RED))

TWILIO_SID = env_str("TWILIO_ACCOUNT_SID")
TWILIO_AUTH = env_str("TWILIO_AUTH_TOKEN")
if TWILIO_SID and TWILIO_AUTH:
    twilio_client = TwilioClient(TWILIO_SID, TWILIO_AUTH)
else:
    twilio_client = None
    print(color("Twilio credentials missing. Call placement will be disabled.", YELLOW))

FROM_NUMBER = env_str("FROM_NUMBER")
FROM_NUMBERS = parse_csv_env("FROM_NUMBERS", [])
TO_NUMBER = env_str("TO_NUMBER")

ALLOWED_COUNTRY_CODES = set(parse_csv_env("ALLOWED_COUNTRY_CODES", ["+1"]))

RECORDING_MODE = env_str("RECORDING_MODE", "off").lower() or "off"
RECORDING_JUR_MODE = env_str("RECORDING_JURISDICTION_MODE", "disable_in_two_party").lower()
TTS_VOICE = env_str("TTS_VOICE", "man")
TTS_LANG = env_str("TTS_LANGUAGE", "en-US")

ROTATE_PROMPTS = env_bool("ROTATE_PROMPTS", True)
ROTATE_STRATEGY = env_str("ROTATE_PROMPTS_STRATEGY", "random").lower()
CALLEE_SILENCE_HANGUP_SECONDS = max(5, min(60, env_int("CALLEE_SILENCE_HANGUP_SECONDS", 8)))

COMPANY_NAME = env_str("COMPANY_NAME", "Acme")
TOPIC = env_str("TOPIC", "vehicle information")

ADMIN_USER = env_str("ADMIN_USER", "admin")
ADMIN_PASSWORD_HASH = env_str("ADMIN_PASSWORD_HASH")  # bcrypt hash of the admin password
HISTORY_CSV_PATH = Path(env_str("HISTORY_CSV_PATH", "./data/call_history.csv")).resolve()
MIRROR_DIR = Path(env_str("MIRROR_TRANSCRIPTS_DIR", "")).resolve() if env_str("MIRROR_TRANSCRIPTS_DIR", "") else None

NONINTERACTIVE = env_bool("NONINTERACTIVE", False)

# Call attempt caps and backoff (lightweight in this single file)
MIN_INTERVAL_SECONDS = env_int("MIN_INTERVAL_SECONDS", 300)
MAX_INTERVAL_SECONDS = env_int("MAX_INTERVAL_SECONDS", 900)
HOURLY_MAX_ATTEMPTS_PER_DEST = env_int("HOURLY_MAX_ATTEMPTS_PER_DEST", 2)
DAILY_MAX_ATTEMPTS_PER_DEST = env_int("DAILY_MAX_ATTEMPTS_PER_DEST", 5)
BACKOFF_STRATEGY = env_str("BACKOFF_STRATEGY", "exponential").lower()

ENABLEMENT_MATRIX = {
    "dual_media_streams": True,
    "recording_mode": RECORDING_MODE,
    "rotate_prompts": ROTATE_PROMPTS,
    "rotate_strategy": ROTATE_STRATEGY,
    "ws_auth": True,
    "admin": bool(ADMIN_PASSWORD_HASH),
    "hot_reload": True,
    "csv_history": True,
}

print(color("Feature matrix:", BOLD))
for k, v in ENABLEMENT_MATRIX.items():
    print(f" - {k}: {v}")

# -------------------------
# Prompts and sanitizer
# -------------------------

BANNED_PHRASES = [
    "This is an automated assistant from Import Engines",
]
BANNED_WORDS = [
    "consent",
]

# Keep prompts short, neutral, and professional; use " || " as a split point for a short pause.
ROTATING_PROMPTS = [
    "I am reaching out regarding {topic}. || Do you have the year, make, and model available?",
    "I am following up about {topic}. || Could you share the year, make, and model?",
    "Quick question on {topic}. || Do you happen to know the year, make, and model?",
    "Calling about {topic}. || Do you have the eighth digit of the VIN handy?",
    "About {topic}. || Can we confirm the year, make, and model to proceed?",
    "I would like to verify details for {topic}. || Is the eighth digit of the VIN available?",
    "Touching base on {topic}. || What is the year, make, and model?",
    "Checking availability for {topic}. || What timeline are you working with?",
    "Following up on {topic}. || What is your budget range and current location?",
    "Regarding {topic}. || Could we confirm availability and approximate lead time?",
]

def sanitize_line(line: str) -> Tuple[str, bool]:
    """
    Remove banned phrases or lines that contain banned words (case-insensitive).
    Returns (sanitized_text, was_sanitized).
    """
    original = line
    lowered = line.lower()
    for phrase in BANNED_PHRASES:
        if phrase.lower() in lowered:
            return ("", True)
    for word in BANNED_WORDS:
        if word in lowered:
            return ("", True)
    return (original, False)

_last_prompt_index: Optional[int] = None

def select_prompt() -> str:
    global _last_prompt_index
    prompts = ROTATING_PROMPTS
    if not ROTATE_PROMPTS:
        idx = 0
    else:
        if ROTATE_STRATEGY == "sequential":
            idx = 0 if _last_prompt_index is None else (_last_prompt_index + 1) % len(prompts)
        else:
            # random with no immediate repeat
            candidates = [i for i in range(len(prompts)) if i != _last_prompt_index]
            idx = random.choice(candidates) if candidates else 0
    _last_prompt_index = idx
    templ = prompts[idx]
    return templ.format(company_name=COMPANY_NAME, topic=TOPIC)

# -------------------------
# WS auth token
# -------------------------

serializer = URLSafeTimedSerializer(app.secret_key, salt="ws-audio")

def issue_ws_token() -> str:
    payload = {"u": session.get("uid") or hashlib.sha256(os.urandom(16)).hexdigest()}
    session["uid"] = payload["u"]
    return serializer.dumps(payload)

def verify_ws_token(token: str, max_age: int = 3600) -> bool:
    try:
        payload = serializer.loads(token, max_age=max_age)
        return bool(payload.get("u"))
    except (BadSignature, SignatureExpired):
        return False

# -------------------------
# In-memory call state
# -------------------------

@dataclass
class CallState:
    call_sid: str
    started_at: dt.datetime = field(default_factory=now_utc)
    prompt_used: str = ""
    transcript: List[Dict[str, Any]] = field(default_factory=list)  # [{role, text, t}]
    partial_buffer: str = ""
    partial_timer: Optional[threading.Timer] = None
    status: str = "in-progress"
    duration_sec: Optional[int] = None
    outcome: str = "unknown"

CALLS: Dict[str, CallState] = {}
CALLS_LOCK = threading.Lock()

def append_transcript(call_sid: str, role: str, text: str, is_final: bool = True) -> None:
    text = (text or "").strip()
    if not text:
        return
    entry = {"role": role, "text": text, "t": utc_iso()}
    with CALLS_LOCK:
        cs = CALLS.get(call_sid)
        if not cs:
            cs = CallState(call_sid=call_sid)
            CALLS[call_sid] = cs
        cs.transcript.append(entry)
    if is_final:
        # Column-style stdout logs for finalized lines only.
        print(f"{role}: {text}")

def _flush_partial_locked(call_sid: str) -> None:
    cs = CALLS.get(call_sid)
    if not cs:
        return
    if cs.partial_timer:
        try:
            cs.partial_timer.cancel()
        except Exception:
            pass
        cs.partial_timer = None
    buf = cs.partial_buffer.strip()
    if buf:
        cs.partial_buffer = ""
        # Commit as finalized callee line
        append_transcript(call_sid, "Callee", buf, is_final=True)

def schedule_partial_flush(call_sid: str, delay_sec: float = 0.55) -> None:
    def _flush():
        with CALLS_LOCK:
            _flush_partial_locked(call_sid)

    with CALLS_LOCK:
        cs = CALLS.get(call_sid)
        if not cs:
            cs = CallState(call_sid=call_sid)
            CALLS[call_sid] = cs
        if cs.partial_timer:
            try:
                cs.partial_timer.cancel()
            except Exception:
                pass
        cs.partial_timer = threading.Timer(delay_sec, _flush)
        cs.partial_timer.daemon = True
        cs.partial_timer.start()

def handle_partial(call_sid: str, text: str) -> None:
    text = (text or "").strip()
    if not text:
        return
    with CALLS_LOCK:
        cs = CALLS.get(call_sid)
        if not cs:
            cs = CallState(call_sid=call_sid)
            CALLS[call_sid] = cs
        # Do not finalize yet; buffer and log as partial (non-final output kept minimal)
        cs.partial_buffer = text
    # Optional: visible debug
    print(color(f"Callee (partial): {text}", CYAN))
    schedule_partial_flush(call_sid)

def handle_final(call_sid: str, text: str) -> None:
    # Commit any partials first, then add final text (avoid duplication if same)
    with CALLS_LOCK:
        cs = CALLS.get(call_sid)
        if not cs:
            cs = CallState(call_sid=call_sid)
            CALLS[call_sid] = cs
        buf = cs.partial_buffer.strip()
        if buf:
            # If identical to final, clear buffer without double-appending
            if buf == (text or "").strip():
                cs.partial_buffer = ""
            else:
                _flush_partial_locked(call_sid)
    if text:
        append_transcript(call_sid, "Callee", text, is_final=True)

def end_call(call_sid: str, status: str, duration_sec: Optional[int]) -> None:
    with CALLS_LOCK:
        cs = CALLS.get(call_sid)
        if not cs:
            return
        # Flush partials on end
        _flush_partial_locked(call_sid)
        cs.status = "completed"
        cs.duration_sec = duration_sec
        cs.outcome = status

    persist_call_history(call_sid)

def persist_call_history(call_sid: str) -> None:
    with CALLS_LOCK:
        cs = CALLS.get(call_sid)
        if not cs:
            return
        
        # Use SQLite database instead of CSV file
        persist_call_history_csv(
            call_sid=cs.call_sid,
            started_at=cs.started_at.isoformat(),
            duration_sec=cs.duration_sec or 0,
            outcome=cs.outcome,
            transcript=json.dumps(cs.transcript, ensure_ascii=False),
            prompt=cs.prompt_used
        )

# -------------------------
# Live audio fan-out hub
# -------------------------

class LiveAudioHub:
    def __init__(self) -> None:
        self.clients: Set[Any] = set()
        self.lock = threading.Lock()

    def add(self, ws) -> None:
        with self.lock:
            self.clients.add(ws)

    def remove(self, ws) -> None:
        with self.lock:
            if ws in self.clients:
                self.clients.remove(ws)

    def broadcast(self, message: Dict[str, Any]) -> None:
        payload = json.dumps(message)
        dead: List[Any] = []
        with self.lock:
            for ws in list(self.clients):
                try:
                    ws.send(payload)
                except Exception:
                    dead.append(ws)
            for d in dead:
                try:
                    self.clients.remove(d)
                except Exception:
                    pass

audio_hub = LiveAudioHub()

# -------------------------
# Hot-reload and admin-triggered restart
# -------------------------

RESTART_EVENT = threading.Event()

if FileSystemEventHandler:
    class SelfFileChangeHandler(FileSystemEventHandler):
        def __init__(self, watch_path: Path) -> None:
            super().__init__()
            self.watch_path = str(watch_path)

        def on_modified(self, event):
            if event and event.src_path and os.path.abspath(event.src_path) == os.path.abspath(self.watch_path):
                print(color("Detected code change; scheduling graceful restart.", YELLOW))
                RESTART_EVENT.set()

def hot_reload_thread(watch_file: Path):
    if not Observer or not FileSystemEventHandler:
        return  # Hot reload disabled if watchdog not available
    
    observer = Observer()
    handler = SelfFileChangeHandler(watch_file)
    observer.schedule(handler, str(watch_file.parent), recursive=False)
    observer.start()
    try:
        while True:
            if RESTART_EVENT.is_set():
                time.sleep(0.5)
                # Exec self to reload
                print(color("Restarting now...", YELLOW))
                python = sys.executable
                os.execv(python, [python] + sys.argv)
            time.sleep(0.25)
    finally:
        observer.stop()
        observer.join()

# -------------------------
# Twilio voice routes
# -------------------------

ONE_SHOT_OPENING_LOCK = threading.Lock()
ONE_SHOT_OPENING: Optional[str] = None

def build_opening_lines() -> List[str]:
    with ONE_SHOT_OPENING_LOCK:
        global ONE_SHOT_OPENING
        if ONE_SHOT_OPENING:
            line = ONE_SHOT_OPENING
            ONE_SHOT_OPENING = None
            sanitized, was_san = sanitize_line(line)
            if was_san:
                print(color("Sanitized one-shot opening line.", YELLOW))
            return [sanitized] if sanitized else []
    prompt = select_prompt()
    sanitized_prompt, was_san = sanitize_line(prompt)
    if was_san:
        print(color("Sanitized rotating prompt.", YELLOW))
    # Opening prefix (configurable here if needed)
    opening_prefix = "Hi there."
    sanitized_prefix, was_san_p = sanitize_line(opening_prefix)
    if was_san_p:
        print(color("Sanitized opening prefix.", YELLOW))
    lines: List[str] = []
    if sanitized_prefix:
        lines.append(sanitized_prefix)
    if sanitized_prompt:
        parts = [p.strip() for p in sanitized_prompt.split("||")]
        for p in parts:
            if p:
                lines.append(p)
    return lines

@app.route("/voice", methods=["POST", "GET"])
def voice():
    # TwiML with dual media streams started immediately and Gather with partial callbacks
    if not PUBLIC_BASE_URL:
        return "Server misconfigured: PUBLIC_BASE_URL required.", 500
    call_sid = request.values.get("CallSid", "")
    response = VoiceResponse()

    # Start Streams immediately for both inbound and outbound audio
    start = Start()
    start.stream(url=f"{PUBLIC_BASE_URL.replace('http:', 'ws:').replace('https:', 'wss:')}/media-in", track="inbound_track")
    start.stream(url=f"{PUBLIC_BASE_URL.replace('http:', 'ws:').replace('https:', 'wss:')}/media-out", track="outbound_track")
    response.append(start)

    lines = build_opening_lines()

    # Gather with configuration
    g = Gather(
        input="speech",
        method="POST",
        action=url_for("transcribe", seq=1, _external=True),
        timeout=str(CALLEE_SILENCE_HANGUP_SECONDS),
        speech_timeout="auto",
        speech_model="phone_call",
        barge_in=True,
        partial_result_callback=url_for("transcribe_partial", stage="dialog", seq=1, _external=True),
        partial_result_callback_method="POST",
        language=TTS_LANG
    )

    # Speak assistant lines while Gather listens (barge-in enabled)
    for i, line in enumerate(lines):
        if not line:
            continue
        append_transcript(call_sid, "Assistant", line, is_final=True)
        g.say(line, voice=TTS_VOICE, language=TTS_LANG)
        # Twilio <Pause length=N> only supports integer seconds; approximate 1 second
        if i < len(lines) - 1:
            g.pause(length=1)

    response.append(g)

    # If no input received (timeout), we can continue or end
    # Keep media streams alive for call duration
    return str(response)

@app.route("/transcribe", methods=["POST"])
def transcribe():
    # Final result from Gather
    call_sid = request.values.get("CallSid", "")
    speech_result = request.values.get("SpeechResult", "")
    if call_sid:
        handle_final(call_sid, speech_result)
    # Continue listening with another Gather cycle if desired (simple end here)
    vr = VoiceResponse()
    # Keep streams alive by adding a short pause; or end call naturally
    vr.pause(length=1)
    return str(vr)

@app.route("/transcribe-partial", methods=["POST"])
def transcribe_partial():
    # Partial result callback from Gather
    call_sid = request.values.get("CallSid", "")
    unstable = request.values.get("UnstableSpeechResult", "") or request.values.get("SpeechResult", "")
    if call_sid and unstable:
        handle_partial(call_sid, unstable)
    return ("", 204)

@app.route("/status", methods=["POST"])
def status():
    # Twilio call status callback
    call_sid = request.values.get("CallSid", "")
    call_status = request.values.get("CallStatus", "")
    duration = request.values.get("CallDuration", None)
    duration_sec = int(duration) if duration and duration.isdigit() else None
    if call_sid:
        end_call(call_sid, call_status, duration_sec)
    return ("", 204)

@app.route("/recording-status", methods=["POST"])
def recording_status():
    # Placeholder for recording status if recording is enabled
    return ("", 204)

# -------------------------
# REST API for controls and exports
# -------------------------

def choose_from_number() -> Optional[str]:
    choices = [n for n in ([FROM_NUMBER] if FROM_NUMBER else []) + FROM_NUMBERS if n]
    choices = [n for n in choices if validate_e164(n)]
    if not choices:
        return None
    return random.choice(choices)

def allowed_destination(to_number: str) -> bool:
    # Allow-list by country code prefix
    return any(to_number.startswith(cc) for cc in ALLOWED_COUNTRY_CODES)

@app.route("/api/scamcalls/call-now", methods=["POST"])
def call_now():
    if not twilio_client:
        return jsonify({"ok": False, "error": "Twilio not configured"}), 400
    to_number = env_str("TO_NUMBER") or TO_NUMBER
    if not to_number or not validate_e164(to_number):
        return jsonify({"ok": False, "error": "Invalid TO_NUMBER"}), 400
    if not allowed_destination(to_number):
        return jsonify({"ok": False, "error": "Destination not allowed"}), 403
    from_number = choose_from_number()
    if not from_number:
        return jsonify({"ok": False, "error": "No valid FROM number configured"}), 400

    # Recording parameters
    record_kwargs: Dict[str, Any] = {}
    if RECORDING_MODE == "off":
        pass
    elif RECORDING_MODE == "mono":
        record_kwargs["record"] = True
        record_kwargs["recordingChannels"] = "mono"
    elif RECORDING_MODE == "dual":
        record_kwargs["record"] = True
        record_kwargs["recordingChannels"] = "dual"
    elif RECORDING_MODE == "ask":
        # In this minimal version, we do not dynamically ask; default to off at placement time
        pass

    try:
        call = twilio_client.calls.create(
            to=to_number,
            from_=from_number,
            url=f"{PUBLIC_BASE_URL}/voice",
            status_callback=f"{PUBLIC_BASE_URL}/status",
            status_callback_event=["initiated", "ringing", "answered", "completed"],
            status_callback_method="POST",
            **record_kwargs,
        )
        with CALLS_LOCK:
            cs = CALLS.get(call.sid)
            if not cs:
                cs = CallState(call_sid=call.sid)
                CALLS[call.sid] = cs
            cs.prompt_used = select_prompt()  # approximate the one that will be spoken
        return jsonify({"ok": True, "sid": call.sid})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/scamcalls/status", methods=["GET"])
def scamcalls_status():
    # Basic status for UI
    data = {
        "public_base_url": PUBLIC_BASE_URL,
        "to_number_masked": mask_number(env_str("TO_NUMBER") or TO_NUMBER),
        "from_numbers": [mask_number(n) for n in ([FROM_NUMBER] if FROM_NUMBER else []) + FROM_NUMBERS],
        "recording_mode": RECORDING_MODE,
        "rotate_prompts": ROTATE_PROMPTS,
        "language": TTS_LANG,
        "voice": TTS_VOICE,
    }
    return jsonify(data)

def mask_number(num: str) -> str:
    if not num:
        return ""
    if len(num) <= 4:
        return "*" * len(num)
    return "*" * (len(num) - 4) + num[-4:]

@app.route("/api/scamcalls/next-opening", methods=["POST"])
def next_opening():
    try:
        payload = request.get_json(force=True, silent=True) or {}
        text = (payload.get("text") or "").strip()
        if not text:
            return jsonify({"ok": False, "error": "Empty text"}), 400
        if len(text) > 150:
            return jsonify({"ok": False, "error": "Max 150 characters"}), 400
        safe, was_san = sanitize_line(text)
        if not safe:
            return jsonify({"ok": False, "error": "Line contained disallowed content"}), 400
        with ONE_SHOT_OPENING_LOCK:
            global ONE_SHOT_OPENING
            ONE_SHOT_OPENING = safe
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route("/api/scamcalls/transcript/<sid>", methods=["GET"])
def get_transcript(sid: str):
    with CALLS_LOCK:
        cs = CALLS.get(sid)
        if not cs:
            return jsonify({"ok": False, "error": "Not found"}), 404
        return jsonify({"ok": True, "transcript": cs.transcript, "prompt": cs.prompt_used})

def load_history_rows() -> List[Dict[str, str]]:
    return load_history_rows_csv()

@app.route("/api/scamcalls/history", methods=["GET"])
def api_history():
    rows = load_history_rows()
    return jsonify({"ok": True, "rows": rows})

def filter_history(rows: List[Dict[str, str]], args: Dict[str, str]) -> List[Dict[str, str]]:
    since = args.get("since")
    until = args.get("until")
    outcome = args.get("outcome")
    limit = args.get("limit")
    include_transcript = args.get("includeTranscript", "true").lower() in TRUE_SET

    def ts_ok(r):
        try:
            started = dt.datetime.fromisoformat(r.get("startedAt", ""))
        except Exception:
            return True
        if since:
            try:
                if started < dt.datetime.fromtimestamp(float(since), tz=dt.timezone.utc):
                    return False
            except Exception:
                pass
        if until:
            try:
                if started > dt.datetime.fromtimestamp(float(until), tz=dt.timezone.utc):
                    return False
            except Exception:
                pass
        return True

    out: List[Dict[str, str]] = []
    for r in rows:
        if outcome and r.get("outcome") != outcome:
            continue
        if not ts_ok(r):
            continue
        rr = dict(r)
        if not include_transcript:
            rr["transcript"] = ""
        out.append(rr)
    if limit:
        try:
            n = int(limit)
            out = out[:max(0, n)]
        except Exception:
            pass
    return out

@app.route("/api/scamcalls/export.csv", methods=["GET"])
def export_csv():
    rows = load_history_rows()
    rows = filter_history(rows, request.args)
    headers = ["callSid", "startedAt", "durationSec", "outcome", "transcript", "prompt"]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=headers)
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r.get(k, "") for k in headers})

    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    resp = send_file(mem, mimetype="text/csv", as_attachment=True, download_name=f"scamcalls_{ts}.csv")
    return resp

@app.route("/api/scamcalls/export.json", methods=["GET"])
def export_json():
    rows = load_history_rows()
    rows = filter_history(rows, request.args)
    return jsonify({"ok": True, "rows": rows})

# -------------------------
# WebSocket routes
# -------------------------

@_sock.route("/media-in")
def media_in(ws):
    # Twilio inbound track
    handle_media_stream(ws, direction="inbound")

@_sock.route("/media-out")
def media_out(ws):
    # Twilio outbound track
    handle_media_stream(ws, direction="outbound")

def handle_media_stream(ws, direction: str):
    try:
        while True:
            msg = ws.receive()
            if msg is None:
                break
            try:
                data = json.loads(msg)
            except Exception:
                continue
            event = data.get("event")
            if event == "start":
                pass
            elif event == "media":
                payload = data.get("media", {}).get("payload", "")
                if payload:
                    audio_hub.broadcast({"type": "media", "direction": direction, "payload": payload})
            elif event == "stop":
                pass
    except Exception:
        pass

@_sock.route("/ws/live-audio")
def ws_live_audio(ws):
    # Validate short-lived auth token bound to session
    token = None
    try:
        # Flask-Sock exposes HTTP query string in environ
        qs = ws.environ.get("QUERY_STRING", "")
        for pair in qs.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                if k == "token":
                    token = v
                    break
    except Exception:
        pass
    if not token or not verify_ws_token(token):
        try:
            ws.send(json.dumps({"type": "error", "error": "unauthorized"}))
        except Exception:
            pass
        ws.close()
        return
    audio_hub.add(ws)
    try:
        while True:
            msg = ws.receive()
            if msg is None:
                break
            # Browser does not send anything; ignore
    except Exception:
        pass
    finally:
        audio_hub.remove(ws)

# -------------------------
# Admin auth and .env editor
# -------------------------

def is_admin() -> bool:
    return bool(session.get("is_admin") is True)

def require_admin():
    if not is_admin():
        return redirect(url_for("login", next=request.path))

def bcrypt_check(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def atomic_write_env(new_content: str) -> None:
    env_path = Path(".env").resolve()
    tmp_path = env_path.with_suffix(".tmp")
    bak_path = env_path.with_suffix(".bak")
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(new_content)
        f.flush()
        os.fsync(f.fileno())
    # Backup
    try:
        if env_path.exists():
            if bak_path.exists():
                bak_path.unlink(missing_ok=True)
            env_path.replace(bak_path)
    except Exception:
        pass
    os.replace(tmp_path, env_path)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if not ADMIN_PASSWORD_HASH:
            error = "Admin is not configured."
        elif username != ADMIN_USER:
            error = "Invalid credentials."
        elif not bcrypt_check(password, ADMIN_PASSWORD_HASH):
            error = "Invalid credentials."
        else:
            session["is_admin"] = True
            return redirect(url_for("admin"))
    return render_template_string(TPL_LOGIN, error=error)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

SAFE_ENV_KEYS = {
    "ACTIVE_HOURS_LOCAL",
    "ACTIVE_DAYS",
    "MIN_INTERVAL_SECONDS",
    "MAX_INTERVAL_SECONDS",
    "HOURLY_MAX_ATTEMPTS_PER_DEST",
    "DAILY_MAX_ATTEMPTS_PER_DEST",
    "BACKOFF_STRATEGY",
    "TTS_VOICE",
    "TTS_LANGUAGE",
    "ROTATE_PROMPTS",
    "ROTATE_PROMPTS_STRATEGY",
    "RECORDING_MODE",
    "RECORDING_JURISDICTION_MODE",
    "COMPANY_NAME",
    "TOPIC",
    "ALLOWED_COUNTRY_CODES",
    "CALLEE_SILENCE_HANGUP_SECONDS",
}

@app.route("/admin", methods=["GET"])
def admin():
    if not is_admin():
        return require_admin()
    # Load .env content to populate safe fields
    env_values = {}
    for k in SAFE_ENV_KEYS:
        env_values[k] = os.getenv(k, "")
    diagnostics = {
        "recent_outcomes": [f"{sid}: {cs.outcome}" for sid, cs in list(CALLS.items())[-10:]],
    }
    return render_template_string(TPL_ADMIN, env_values=env_values, diagnostics=diagnostics)

@app.route("/admin/save", methods=["POST"])
def admin_save():
    if not is_admin():
        return require_admin()
    # Read current .env; merge safe changes
    env_path = Path(".env")
    current_lines: List[str] = []
    if env_path.exists():
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                current_lines = f.read().splitlines()
        except Exception:
            current_lines = []
    env_map: Dict[str, str] = {}
    for line in current_lines:
        if not line or line.strip().startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env_map[k.strip()] = v

    for k in SAFE_ENV_KEYS:
        if k in request.form:
            env_map[k] = str(request.form.get(k, "")).strip()

    # Recreate .env content
    content_lines = []
    for k, v in env_map.items():
        content_lines.append(f"{k}={v}")
    new_content = "\n".join(content_lines) + "\n"
    try:
        atomic_write_env(new_content)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    return jsonify({"ok": True})

@app.route("/admin/restart", methods=["POST"])
def admin_restart():
    if not is_admin():
        return require_admin()
    RESTART_EVENT.set()
    return jsonify({"ok": True})

# -------------------------
# UI pages
# -------------------------

@app.route("/")
def index():
    return redirect(url_for("scamcalls"))

@app.route("/scamcalls")
def scamcalls():
    token = issue_ws_token()
    return render_template_string(TPL_SCAMCALLS, ws_token=token)

@app.route("/scamcalls/history")
def scamcalls_history():
    rows = load_history_rows()
    return render_template_string(TPL_HISTORY, rows=rows)

@app.route("/api/ws-token", methods=["GET"])
def api_ws_token():
    return jsonify({"token": issue_ws_token()})

# -------------------------
# HTML Templates (embedded)
# -------------------------

TPL_SCAMCALLS = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Scam Calls - Live</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
{{ CSS_BASE }}
</style>
</head>
<body>
<header>
  <h1>Outbound Caller - Live</h1>
  <nav>
    <a href="{{ url_for('scamcalls') }}">Live</a> |
    <a href="{{ url_for('scamcalls_history') }}">History</a> |
    <a href="{{ url_for('admin') }}">Admin</a>
  </nav>
</header>

<main>
  <section class="controls">
    <button id="callNowBtn">Call now</button>
    <button id="listenBtn">Listen Live</button>
    <button id="modifyScriptBtn">Modify Script</button>
  </section>

  <section class="status" id="statusBox">
    <h2>Status</h2>
    <pre id="statusPre">Loading...</pre>
  </section>

  <section class="audio">
    <h2>Live Audio</h2>
    <div class="sliders">
      <label>Inbound gain <input id="gainIn" type="range" min="0" max="2" value="1" step="0.01"></label>
      <label>Outbound gain <input id="gainOut" type="range" min="0" max="2" value="1" step="0.01"></label>
      <label>Master gain <input id="gainMaster" type="range" min="0" max="2" value="1" step="0.01"></label>
    </div>
    <div id="audioStatus">Not connected.</div>
  </section>

  <section class="transcript">
    <h2>Transcript</h2>
    <div id="transcriptBox" class="transcript-box"></div>
  </section>
</main>

<div id="modalBackdrop" class="backdrop" hidden>
  <div class="modal">
    <h3>One-shot opening line</h3>
    <textarea id="openingText" maxlength="150" placeholder="Enter a short, polite opening line..."></textarea>
    <div class="modal-actions">
      <button id="saveOpeningBtn">Save</button>
      <button id="cancelOpeningBtn">Cancel</button>
    </div>
    <div id="openingError" class="error"></div>
  </div>
</div>

<script>
const WS_TOKEN = {{ ws_token|tojson }};
{{ JS_BASE }}
</script>
</body>
</html>
"""

TPL_HISTORY = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Scam Calls - History</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
{{ CSS_BASE }}
table { width: 100%; border-collapse: collapse; }
th, td { border: 1px solid #444; padding: 6px; }
</style>
</head>
<body>
<header>
  <h1>Outbound Caller - History</h1>
  <nav>
    <a href="{{ url_for('scamcalls') }}">Live</a> |
    <a href="{{ url_for('scamcalls_history') }}">History</a> |
    <a href="{{ url_for('admin') }}">Admin</a>
  </nav>
</header>

<main>
  <section class="downloads">
    <a class="btn" href="{{ url_for('export_csv') }}">Download CSV</a>
    <a class="btn" href="{{ url_for('export_json') }}" target="_blank">View JSON</a>
  </section>

  <section class="history">
    <table>
      <thead>
        <tr><th>CallSid</th><th>Started</th><th>Duration (s)</th><th>Outcome</th><th>Prompt</th></tr>
      </thead>
      <tbody>
        {% for r in rows %}
        <tr>
          <td><a href="#" onclick="showTranscript('{{ r.get('callSid','')|e }}'); return false;">{{ r.get("callSid","") }}</a></td>
          <td>{{ r.get("startedAt","") }}</td>
          <td>{{ r.get("durationSec","") }}</td>
          <td>{{ r.get("outcome","") }}</td>
          <td>{{ r.get("prompt","") }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>

  <section>
    <h2>Transcript</h2>
    <pre id="transcriptPre">Click a CallSid to load transcript.</pre>
  </section>
</main>

<script>
async function showTranscript(sid) {
  const r = await fetch(`/api/scamcalls/transcript/${encodeURIComponent(sid)}`);
  if (!r.ok) { alert('Failed to load transcript'); return; }
  const data = await r.json();
  if (!data.ok) { alert('Not found'); return; }
  const lines = data.transcript || [];
  const text = lines.map(x => `${x.role}: ${x.text}`).join("\n");
  document.getElementById('transcriptPre').textContent = text || "(empty)";
}
</script>
</body>
</html>
"""

TPL_LOGIN = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Admin Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
{{ CSS_BASE }}
form { max-width: 360px; margin: 0 auto; }
label { display: block; margin-top: 8px; }
input[type="text"], input[type="password"] { width: 100%; padding: 8px; }
.error { color: #c33; margin-top: 8px; }
</style>
</head>
<body>
<header>
  <h1>Admin Login</h1>
</header>
<main>
  {% if error %}
    <div class="error">{{ error }}</div>
  {% endif %}
  <form method="post">
    <label>Username
      <input name="username" type="text" autocomplete="username">
    </label>
    <label>Password
      <input name="password" type="password" autocomplete="current-password">
    </label>
    <button type="submit">Login</button>
  </form>
</main>
</body>
</html>
"""

TPL_ADMIN = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
{{ CSS_BASE }}
form { max-width: 720px; margin: 0 auto; }
label { display: block; margin-top: 8px; }
input[type="text"] { width: 100%; padding: 8px; }
.btnrow { margin-top: 12px; }
pre { background: #111; padding: 12px; overflow: auto; }
</style>
</head>
<body>
<header>
  <h1>Admin</h1>
  <nav>
    <a href="{{ url_for('scamcalls') }}">Live</a> |
    <a href="{{ url_for('scamcalls_history') }}">History</a>
  </nav>
</header>
<main>
  <section>
    <h2>Safe .env Editor</h2>
    <form id="envForm">
      {% for k, v in env_values.items() %}
      <label>{{ k }}
        <input type="text" name="{{ k }}" value="{{ v|e }}">
      </label>
      {% endfor %}
      <div class="btnrow">
        <button type="button" id="saveEnvBtn">Save</button>
        <button type="button" id="restartBtn">Restart</button>
      </div>
      <div id="envMsg"></div>
    </form>
    <form method="post" action="{{ url_for('logout') }}">
      <button type="submit">Logout</button>
    </form>
  </section>

  <section>
    <h2>Diagnostics</h2>
    <pre>{{ diagnostics|tojson(indent=2) }}</pre>
  </section>
</main>

<script>
document.getElementById('saveEnvBtn').addEventListener('click', async () => {
  const form = document.getElementById('envForm');
  const data = new FormData(form);
  const r = await fetch('/admin/save', { method: 'POST', body: data });
  const d = await r.json().catch(() => ({}));
  document.getElementById('envMsg').textContent = d.ok ? 'Saved.' : ('Error: ' + (d.error || 'unknown'));
});
document.getElementById('restartBtn').addEventListener('click', async () => {
  const r = await fetch('/admin/restart', { method: 'POST' });
  const d = await r.json().catch(() => ({}));
  if (d.ok) {
    document.getElementById('envMsg').textContent = 'Restarting...';
    setTimeout(() => location.reload(), 1500);
  } else {
    document.getElementById('envMsg').textContent = 'Error requesting restart.';
  }
});
</script>
</body>
</html>
"""

# -------------------------
# Embedded CSS and JS
# -------------------------

CSS_BASE = r"""
:root {
  --bg: #0b0c10;
  --panel: #1f2833;
  --text: #c5c6c7;
  --accent: #66fcf1;
  --accent2: #45a29e;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
}
header {
  background: var(--panel);
  padding: 12px;
  border-bottom: 1px solid #333;
}
header h1 { margin: 0 0 8px 0; color: var(--accent); }
nav a { color: var(--accent2); margin-right: 8px; text-decoration: none; }
main { padding: 16px; }
.controls button, .btn { padding: 8px 12px; margin-right: 8px; background: var(--accent2); border: none; color: #fff; cursor: pointer; }
.controls { margin-bottom: 16px; }
.status pre { background: #111; padding: 12px; overflow: auto; }
.transcript-box {
  background: #111;
  padding: 12px;
  min-height: 240px;
  border: 1px solid #333;
  white-space: pre-wrap;
}
.sliders label { display: inline-block; margin-right: 12px; }
.backdrop {
  position: fixed; inset: 0; background: rgba(0,0,0,0.5);
  display: flex; align-items: center; justify-content: center;
}
.modal { background: var(--panel); padding: 16px; width: 480px; max-width: 96vw; border: 1px solid #333; }
.modal textarea { width: 100%; height: 120px; }
.modal-actions { display: flex; gap: 8px; margin-top: 8px; }
.error { color: #ff6b6b; }
"""

JS_BASE = r"""
// Minimal client: status polling, call-now, modify script modal, and dual-track audio playback.
const statusPre = document.getElementById('statusPre');
const transcriptBox = document.getElementById('transcriptBox');
const modalBackdrop = document.getElementById('modalBackdrop');
const openingText = document.getElementById('openingText');
const openingError = document.getElementById('openingError');

document.getElementById('callNowBtn').addEventListener('click', async () => {
  disableBtn('callNowBtn', true);
  const r = await fetch('/api/scamcalls/call-now', { method: 'POST' });
  const d = await r.json().catch(()=>({}));
  if (!d.ok) alert('Failed to place call: ' + (d.error || 'unknown'));
  setTimeout(() => disableBtn('callNowBtn', false), 1500);
});

document.getElementById('modifyScriptBtn').addEventListener('click', () => {
  openingText.value = '';
  openingError.textContent = '';
  modalBackdrop.hidden = false;
});
document.getElementById('cancelOpeningBtn').addEventListener('click', () => {
  modalBackdrop.hidden = true;
});
document.getElementById('saveOpeningBtn').addEventListener('click', async () => {
  const text = openingText.value.trim();
  openingError.textContent = '';
  if (!text) { openingError.textContent = 'Enter a line.'; return; }
  const r = await fetch('/api/scamcalls/next-opening', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({text})
  });
  const d = await r.json().catch(()=>({}));
  if (!d.ok) {
    openingError.textContent = d.error || 'Failed to save.';
    return;
  }
  modalBackdrop.hidden = true;
});

async function refreshStatus() {
  const r = await fetch('/api/scamcalls/status');
  const d = await r.json().catch(()=>({}));
  statusPre.textContent = JSON.stringify(d, null, 2);
}
setInterval(refreshStatus, 3000);
refreshStatus();

function disableBtn(id, b) {
  const el = document.getElementById(id);
  if (el) el.disabled = !!b;
}

// Transcript: subscribe to in-memory live log by polling the latest active call (simplified)
let recentLines = [];
function renderTranscript(lines) {
  transcriptBox.textContent = lines.map(x => `${x.t}  ${x.role}: ${x.text}`).join('\n');
}

// Live audio playback with dual gain controls
let ws = null;
let audioCtx = null;
let gainIn = null, gainOut = null, gainMaster = null;
let sourceIn = null, sourceOut = null;
let scriptIn = null, scriptOut = null;

const gainInEl = document.getElementById('gainIn');
const gainOutEl = document.getElementById('gainOut');
const gainMasterEl = document.getElementById('gainMaster');
gainInEl.addEventListener('input', () => { if (gainIn) gainIn.gain.value = parseFloat(gainInEl.value); });
gainOutEl.addEventListener('input', () => { if (gainOut) gainOut.gain.value = parseFloat(gainOutEl.value); });
gainMasterEl.addEventListener('input', () => { if (gainMaster) gainMaster.gain.value = parseFloat(gainMasterEl.value); });

document.getElementById('listenBtn').addEventListener('click', startListening);

async function startListening() {
  if (ws && ws.readyState === WebSocket.OPEN) return;

  if (!audioCtx) {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    gainMaster = audioCtx.createGain();
    gainMaster.gain.value = parseFloat(gainMasterEl.value);
    gainMaster.connect(audioCtx.destination);

    // Inbound chain
    gainIn = audioCtx.createGain();
    gainIn.gain.value = parseFloat(gainInEl.value);
    gainIn.connect(gainMaster);

    // Outbound chain
    gainOut = audioCtx.createGain();
    gainOut.gain.value = parseFloat(gainOutEl.value);
    gainOut.connect(gainMaster);

    // Script processors per channel
    scriptIn = audioCtx.createScriptProcessor(4096, 1, 1);
    scriptIn.connect(gainIn);
    scriptOut = audioCtx.createScriptProcessor(4096, 1, 1);
    scriptOut.connect(gainOut);
  }

  const token = WS_TOKEN || (await (await fetch('/api/ws-token')).json()).token;
  const wsUrl = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws/live-audio?token=' + encodeURIComponent(token);

  ws = new WebSocket(wsUrl);
  ws.onopen = () => {
    document.getElementById('audioStatus').textContent = 'Connected.';
  };
  ws.onclose = () => {
    document.getElementById('audioStatus').textContent = 'Disconnected.';
  };
  ws.onerror = () => {
    document.getElementById('audioStatus').textContent = 'WebSocket error.';
  };
  ws.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.type === 'media') {
        const wav = muLawDecode(base64ToBytes(msg.payload));
        playPcm(wav, msg.direction === 'inbound' ? scriptIn : scriptOut);
      }
    } catch (e) {}
  };
}

// Utilities: mu-law decode (8kHz, mono), 20ms frames expected
function base64ToBytes(b64) {
  const bin = atob(b64);
  const len = bin.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function muLawDecode(u8) {
  // Returns Float32Array PCM
  const n = u8.length;
  const out = new Float32Array(n);
  for (let i = 0; i < n; i++) {
    let u = u8[i];
    u = ~u & 0xff;
    let sign = (u & 0x80) ? -1 : 1;
    let exponent = (u >> 4) & 0x07;
    let mantissa = u & 0x0F;
    let magnitude = ((mantissa << 1) + 33) << (exponent + 2);
    out[i] = sign * (magnitude / 32768);
  }
  return out;
}
function playPcm(samples, node) {
  if (!audioCtx || !node) return;
  // Use a buffer source for continuous playback
  const buf = audioCtx.createBuffer(1, samples.length, 8000);
  buf.copyToChannel(samples, 0, 0);
  const src = audioCtx.createBufferSource();
  src.buffer = buf;
  src.connect(node);
  src.start();
}
"""

# Inject CSS and JS into templates at render time
def _inject_assets(template: str, **kwargs) -> str:
    return render_template_string(template, CSS_BASE=CSS_BASE, JS_BASE=JS_BASE, **kwargs)

# Override render_template_string to inject CSS/JS
render_template_string = _inject_assets

# -------------------------
# Main entrypoint
# -------------------------

def main():
    # Initialize SQLite database
    init_database()
    
    # Start hot-reload watcher thread (watch this file)
    watch_file = Path(__file__).resolve()
    t = threading.Thread(target=hot_reload_thread, args=(watch_file,), daemon=True)
    t.start()

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    # Use Flask built-in server without debug reloader; websockets require threaded server.
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)

if __name__ == "__main__":
    # Basic validation logs (do not leak secrets)
    if FROM_NUMBER and not validate_e164(FROM_NUMBER):
        print(color("Warning: FROM_NUMBER is not in E.164 format.", YELLOW))
    for n in FROM_NUMBERS:
        if not validate_e164(n):
            print(color(f"Warning: FROM_NUMBERS contains invalid value: {n}", YELLOW))
    if TO_NUMBER and not validate_e164(TO_NUMBER):
        print(color("Warning: TO_NUMBER is not in E.164 format.", YELLOW))
    main()
