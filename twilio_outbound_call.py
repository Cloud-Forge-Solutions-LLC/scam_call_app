#!/usr/bin/env python3
"""
Scam Call Console: Outbound caller service with admin UI, pacing, Twilio voice,
optional Media Streams, live transcript API, and clean shutdown.

Updates in this version:
- Graceful termination: Ctrl+C (SIGINT) and SIGTERM now stop the server and background threads cleanly.
- Wait-to-speak: Wait for the callee to speak first before the assistant starts talking.
- Alternating voice per call: Switches assistant TTS voice between male and female every other call.
- Rotating dialog: Each call uses a different dialog set (will cycle through the list).
- Dialogs may include harsh language as requested.

Bug fixes in this version:
- Manual-call suppression: Manual calls were being suppressed as "busy" due to a pre-set pending flag.
  The manual path now only blocks when an actual call SID is active.
- UI accuracy: The status and live endpoints now report "in progress" only when a real CallSid is active,
  not merely pending, so the UI no longer shows a call in progress when none has started yet.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import random
import re
import signal
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

# Optional bcrypt for admin auth
try:
    import bcrypt  # type: ignore
except Exception:
    bcrypt = None  # type: ignore

# Twilio client and TwiML helpers
try:
    from twilio.rest import Client  # type: ignore
except Exception:
    Client = None  # type: ignore

try:
    from twilio.twiml.voice_response import VoiceResponse, Start, Stream, Gather  # type: ignore
except Exception:
    VoiceResponse = None  # type: ignore
    Start = None  # type: ignore
    Stream = None  # type: ignore
    Gather = None  # type: ignore

# Optional ngrok
try:
    from pyngrok import ngrok as ngrok_lib  # type: ignore
except Exception:
    ngrok_lib = None  # type: ignore

# Optional WebSocket support for Media Streams
_sock = None
try:
    from flask_sock import Sock  # type: ignore
except Exception:
    Sock = None  # type: ignore


app = Flask(__name__, static_folder="static", template_folder="templates")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)  # type: ignore
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(32))

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

TRUE_SET = {"1", "true", "yes", "on", "y", "t"}


def _parse_bool(s: Optional[str], default: bool = False) -> bool:
    if s is None:
        return default
    return str(s).strip().lower() in TRUE_SET


def _parse_int(s: Optional[str], default: int) -> int:
    try:
        return int(str(s).strip())
    except Exception:
        return default


def _parse_csv(s: Optional[str]) -> List[str]:
    if not s:
        return []
    return [p.strip() for p in str(s).split(",") if p.strip()]


def _now_local() -> datetime:
    try:
        return datetime.now().astimezone()
    except Exception:
        return datetime.now()


def _load_dotenv_pairs(path: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    p = Path(path)
    if not p.exists():
        return pairs
    try:
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
            if not m:
                continue
            key = m.group(1)
            val = m.group(2)
            if len(val) >= 2 and ((val[0] == val[-1] == '"') or (val[0] == val[-1] == "'")):
                val = val[1:-1]
            pairs.append((key, val))
    except Exception as e:
        logging.error("Failed to read .env pairs: %s", e)
    return pairs


def _overlay_env_from_dotenv(path: str) -> None:
    for k, v in _load_dotenv_pairs(path):
        if k not in os.environ:
            os.environ[k] = v


_overlay_env_from_dotenv(".env")


@dataclass
class RuntimeConfig:
    to_number: str = ""
    from_number: str = ""
    from_numbers: List[str] = field(default_factory=list)

    active_hours_local: str = "09:00-18:00"
    active_days: List[str] = field(default_factory=lambda: ["Mon", "Tue", "Wed", "Thu", "Fri"])
    min_interval_seconds: int = 120
    max_interval_seconds: int = 420
    hourly_max_attempts: int = 3
    daily_max_attempts: int = 20

    admin_user: Optional[str] = None
    admin_password_hash: Optional[str] = None

    tts_voice: str = "man"
    tts_language: str = "en-US"
    rotate_prompts: bool = True
    rotate_prompts_strategy: str = "random"

    company_name: str = ""
    topic: str = ""

    callee_silence_hangup_seconds: int = 8

    recording_mode: str = "off"
    recording_jurisdiction_mode: str = "disable_in_two_party"

    public_base_url: Optional[str] = None
    use_ngrok: bool = False
    enable_media_streams: bool = False

    flask_host: str = "0.0.0.0"
    flask_port: int = 8080
    flask_debug: bool = False


_runtime = RuntimeConfig()


def _normalize_day_name(s: str) -> Optional[str]:
    if not s:
        return None
    t = s.strip().lower()
    mapping = {
        "mon": "Mon",
        "monday": "Mon",
        "tue": "Tue",
        "tues": "Tue",
        "tuesday": "Tue",
        "wed": "Wed",
        "weds": "Wed",
        "wednesday": "Wed",
        "thu": "Thu",
        "thur": "Thu",
        "thurs": "Thu",
        "thursday": "Thu",
        "fri": "Fri",
        "friday": "Fri",
        "sat": "Sat",
        "saturday": "Sat",
        "sun": "Sun",
        "sunday": "Sun",
    }
    return mapping.get(t)


def _load_runtime_from_env() -> None:
    _runtime.to_number = (os.environ.get("TO_NUMBER") or "").strip()
    _runtime.from_number = (os.environ.get("FROM_NUMBER") or "").strip()
    _runtime.from_numbers = _parse_csv(os.environ.get("FROM_NUMBERS"))

    _runtime.active_hours_local = (os.environ.get("ACTIVE_HOURS_LOCAL") or "09:00-18:00").strip()
    days = _parse_csv(os.environ.get("ACTIVE_DAYS") or "Mon,Tue,Wed,Thu,Fri")
    _runtime.active_days = [d for d in ([_normalize_day_name(x) for x in days]) if d]

    _runtime.min_interval_seconds = max(30, _parse_int(os.environ.get("MIN_INTERVAL_SECONDS"), 120))
    _runtime.max_interval_seconds = max(_runtime.min_interval_seconds, _parse_int(os.environ.get("MAX_INTERVAL_SECONDS"), 420))
    _runtime.hourly_max_attempts = max(1, _parse_int(os.environ.get("HOURLY_MAX_ATTEMPTS_PER_DEST"), 3))
    _runtime.daily_max_attempts = max(_runtime.hourly_max_attempts, _parse_int(os.environ.get("DAILY_MAX_ATTEMPTS_PER_DEST"), 20))

    _runtime.rotate_prompts = _parse_bool(os.environ.get("ROTATE_PROMPTS"), True)
    _runtime.rotate_prompts_strategy = (os.environ.get("ROTATE_PROMPTS_STRATEGY") or "random").strip().lower()

    _runtime.tts_voice = (os.environ.get("TTS_VOICE") or "man").strip()
    _runtime.tts_language = (os.environ.get("TTS_LANGUAGE") or "en-US").strip()

    _runtime.recording_mode = (os.environ.get("RECORDING_MODE") or "off").strip().lower()
    _runtime.recording_jurisdiction_mode = (os.environ.get("RECORDING_JURISDICTION_MODE") or "disable_in_two_party").strip().lower()

    _runtime.company_name = (os.environ.get("COMPANY_NAME") or "").strip()
    _runtime.topic = (os.environ.get("TOPIC") or "").strip()

    _runtime.callee_silence_hangup_seconds = max(3, min(60, _parse_int(os.environ.get("CALLEE_SILENCE_HANGUP_SECONDS"), 8)))

    _runtime.public_base_url = (os.environ.get("PUBLIC_BASE_URL") or "").strip() or None
    _runtime.use_ngrok = _parse_bool(os.environ.get("USE_NGROK"), False)
    _runtime.enable_media_streams = _parse_bool(os.environ.get("ENABLE_MEDIA_STREAMS"), False)

    _runtime.flask_host = (os.environ.get("FLASK_HOST") or "0.0.0.0").strip() or "0.0.0.0"
    _runtime.flask_port = _parse_int(os.environ.get("FLASK_PORT"), 8080)
    _runtime.flask_debug = _parse_bool(os.environ.get("FLASK_DEBUG"), False)


_load_runtime_from_env()

_EDITABLE_ENV_KEYS = [
    "TO_NUMBER",
    "FROM_NUMBER",
    "FROM_NUMBERS",
    "ACTIVE_HOURS_LOCAL",
    "ACTIVE_DAYS",
    "MIN_INTERVAL_SECONDS",
    "MAX_INTERVAL_SECONDS",
    "HOURLY_MAX_ATTEMPTS_PER_DEST",
    "DAILY_MAX_ATTEMPTS_PER_DEST",
    "RECORDING_MODE",
    "RECORDING_JURISDICTION_MODE",
    "TTS_VOICE",
    "TTS_LANGUAGE",
    "ROTATE_PROMPTS",
    "ROTATE_PROMPTS_STRATEGY",
    "COMPANY_NAME",
    "TOPIC",
    "ALLOWED_COUNTRY_CODES",
    "CALLEE_SILENCE_HANGUP_SECONDS",
    "USE_NGROK",
    "ENABLE_MEDIA_STREAMS",
    "NONINTERACTIVE",
    "LOG_COLOR",
    "FLASK_HOST",
    "FLASK_PORT",
    "FLASK_DEBUG",
    "PUBLIC_BASE_URL",
]

_SECRET_ENV_KEYS = {
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "ADMIN_PASSWORD_HASH",
    "ADMIN_USER",
    "FLASK_SECRET",
}


def _current_env_editable_pairs() -> List[Tuple[str, str]]:
    effective: Dict[str, str] = {}
    for k in _EDITABLE_ENV_KEYS:
        effective[k] = (os.environ.get(k) or "").strip()
    try:
        env_path = Path(".env")
        if env_path.exists():
            for k, v in _load_dotenv_pairs(str(env_path)):
                if k in _EDITABLE_ENV_KEYS:
                    effective[k] = (v or "").strip()
    except Exception:
        pass
    return [(k, effective.get(k, "")) for k in _EDITABLE_ENV_KEYS]


def _load_dotenv_for_write() -> List[str]:
    p = Path(".env")
    if not p.exists():
        return []
    try:
        with p.open("r", encoding="utf-8") as f:
            return f.readlines()
    except Exception:
        return []


def _write_env_updates_preserving_comments(updates: Dict[str, str]) -> None:
    env_path = Path(".env")
    try:
        lines = _load_dotenv_for_write()
        key_to_idx: Dict[str, int] = {}
        for idx, raw in enumerate(lines):
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            eq = s.find("=")
            if eq <= 0:
                continue
            k = s[:eq].strip()
            if k in _EDITABLE_ENV_KEYS:
                key_to_idx[k] = idx
        content = list(lines)
        for k, v in updates.items():
            if k not in _EDITABLE_ENV_KEYS:
                continue
            safe_v = "" if v is None else str(v)
            new_line = f"{k}={safe_v}\n"
            if k in key_to_idx:
                content[key_to_idx[k]] = new_line
            else:
                if content and not content[-1].endswith("\n"):
                    content[-1] = content[-1] + "\n"
                content.append(new_line)
        tmp = env_path.with_suffix(".tmp")
        bak = env_path.with_suffix(".bak")
        with open(tmp, "w", encoding="utf-8") as f:
            f.writelines(content)
            f.flush()
        try:
            if env_path.exists():
                if bak.exists():
                    try:
                        bak.unlink()
                    except Exception:
                        pass
                env_path.replace(bak)
        except Exception:
            pass
        os.replace(tmp, env_path)
    except Exception as e:
        logging.error("Failed writing .env: %s", e)


def _apply_env_updates(updates: Dict[str, str]) -> None:
    _write_env_updates_preserving_comments(updates)
    for k, v in updates.items():
        if k in _EDITABLE_ENV_KEYS and k not in _SECRET_ENV_KEYS:
            os.environ[k] = "" if v is None else str(v)
    _load_runtime_from_env()


# Attempt pacing
_attempts_lock = threading.Lock()
_dest_attempts: Dict[str, List[float]] = {}
_next_call_epoch_s_lock = threading.Lock()
_next_call_epoch_s: Optional[int] = None
_interval_start_epoch_s: Optional[int] = None
_interval_total_seconds: Optional[int] = None


def _prune_attempts(now_ts: int, to_number: str) -> None:
    with _attempts_lock:
        lst = _dest_attempts.get(to_number, [])
        cutoff = now_ts - 24 * 3600
        _dest_attempts[to_number] = [t for t in lst if t >= cutoff]


def _note_attempt(now_ts: float, to_number: str) -> None:
    with _attempts_lock:
        _dest_attempts.setdefault(to_number, []).append(now_ts)


def _within_active_window(now_local: datetime) -> bool:
    try:
        start_str, end_str = (_runtime.active_hours_local or "09:00-18:00").split("-", 1)
        sh, sm = [int(x) for x in start_str.split(":")]
        eh, em = [int(x) for x in end_str.split(":")]
    except Exception:
        sh, sm, eh, em = 9, 0, 18, 0
    wd_map = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    today = wd_map[now_local.weekday()]
    if _runtime.active_days and today not in _runtime.active_days:
        return False
    t_minutes = now_local.hour * 60 + now_local.minute
    start_m = sh * 60 + sm
    end_m = eh * 60 + em
    if start_m <= end_m:
        return start_m <= t_minutes <= end_m
    return t_minutes >= start_m or t_minutes <= end_m


def _can_attempt(now_ts: int, to_number: str) -> Tuple[bool, int]:
    _prune_attempts(now_ts, to_number)
    with _attempts_lock:
        lst = _dest_attempts.get(to_number, [])
        last_hour = [t for t in lst if t >= now_ts - 3600]
        if len(last_hour) >= _runtime.hourly_max_attempts:
            oldest = min(last_hour) if last_hour else now_ts
            return False, max(1, (oldest + 3600) - now_ts)
        if len(lst) >= _runtime.daily_max_attempts:
            return False, 3600
    return True, 0


def _compute_next_interval_seconds() -> int:
    lo = max(30, int(_runtime.min_interval_seconds))
    hi = max(lo, int(_runtime.max_interval_seconds))
    if lo == hi:
        return lo
    return random.randint(lo, hi)


# Twilio client
_twilio_client: Optional[Client] = None


def _ensure_twilio_client() -> Optional[Client]:
    global _twilio_client
    if _twilio_client is not None:
        return _twilio_client
    if Client is None:
        logging.error("Twilio SDK not available. Install with: pip install twilio")
        return None
    sid = os.environ.get("TWILIO_ACCOUNT_SID")
    tok = os.environ.get("TWILIO_AUTH_TOKEN")
    if not sid or not tok:
        logging.error("Missing TWILIO_ACCOUNT_SID or TWILIO_AUTH_TOKEN in environment.")
        return None
    _twilio_client = Client(sid, tok)
    return _twilio_client


def _choose_from_number() -> Optional[str]:
    if _runtime.from_numbers:
        return random.choice(_runtime.from_numbers)
    return _runtime.from_number or None


# Background dialer and state
_manual_call_requested = threading.Event()
_stop_requested = threading.Event()
_dialer_thread = None  # started in main()

# Track active and pending (pre-callback) call states
_CURRENT_CALL_LOCK = threading.Lock()
_CURRENT_CALL_SID: Optional[str] = None

# Pending is used to block duplicate placements between calls.create and Twilio callbacks
_PENDING_LOCK = threading.Lock()
_PENDING_UNTIL_TS: Optional[float] = None
_PENDING_TTL_SECONDS = 90.0  # safety window; auto-clears on /status initiated or /voice


def _set_current_call_sid(sid: Optional[str]) -> None:
    global _CURRENT_CALL_SID
    with _CURRENT_CALL_LOCK:
        _CURRENT_CALL_SID = sid


def _get_current_call_sid() -> Optional[str]:
    with _CURRENT_CALL_LOCK:
        return _CURRENT_CALL_SID


def _mark_outgoing_pending() -> None:
    global _PENDING_UNTIL_TS
    with _PENDING_LOCK:
        _PENDING_UNTIL_TS = time.time() + _PENDING_TTL_SECONDS


def _clear_outgoing_pending() -> None:
    global _PENDING_UNTIL_TS
    with _PENDING_LOCK:
        _PENDING_UNTIL_TS = None


def _is_outgoing_pending() -> bool:
    global _PENDING_UNTIL_TS
    with _PENDING_LOCK:
        if _PENDING_UNTIL_TS is None:
            return False
        if time.time() >= _PENDING_UNTIL_TS:
            _PENDING_UNTIL_TS = None
            return False
        return True


def _is_call_busy() -> bool:
    return (_get_current_call_sid() is not None) or _is_outgoing_pending()


# Dialog rotation and per-call parameters
@dataclass
class CallParams:
    voice: str
    dialog_idx: int


# Dialog sets. These rotate each call (mild harsh language by request).
_DIALOGS: List[List[str]] = [
    ["Where is my refund?", "Stop wasting my time."],
    ["Do not stall me.", "Answer the question now."],
    ["Cut the nonsense.", "I am not playing games."],
    ["You clearly are not prepared.", "Get this together now."],
    ["I expect clear answers.", "Do not try to dodge this."],
    ["Enough delays.", "Be direct with me."],
]

_CALL_PARAMS_BY_SID: Dict[str, CallParams] = {}
_PENDING_CALL_PARAMS: Optional[CallParams] = None
_PLACED_CALL_COUNT = 0
_LAST_DIALOG_IDX = -1
_PARAMS_LOCK = threading.Lock()


def _select_next_call_params() -> CallParams:
    global _PLACED_CALL_COUNT, _LAST_DIALOG_IDX
    with _PARAMS_LOCK:
        _PLACED_CALL_COUNT += 1
        voice = "man" if (_PLACED_CALL_COUNT % 2 == 1) else "woman"  # alternate voice each call
        _LAST_DIALOG_IDX = (_LAST_DIALOG_IDX + 1) % max(1, len(_DIALOGS))
        return CallParams(voice=voice, dialog_idx=_LAST_DIALOG_IDX)


def _prepare_params_for_next_call() -> None:
    global _PENDING_CALL_PARAMS
    with _PARAMS_LOCK:
        _PENDING_CALL_PARAMS = _select_next_call_params()


def _assign_params_to_sid(sid: str) -> None:
    global _PENDING_CALL_PARAMS
    if not sid:
        return
    with _PARAMS_LOCK:
        if _PENDING_CALL_PARAMS is None:
            _PENDING_CALL_PARAMS = _select_next_call_params()
        _CALL_PARAMS_BY_SID[sid] = _PENDING_CALL_PARAMS
        _PENDING_CALL_PARAMS = None


def _get_params_for_sid(sid: str) -> CallParams:
    with _PARAMS_LOCK:
        cp = _CALL_PARAMS_BY_SID.get(sid)
        if cp:
            return cp
        return CallParams(voice=_runtime.tts_voice or "man", dialog_idx=0)


def _get_dialog_lines(idx: int) -> List[str]:
    if not _DIALOGS:
        return ["Hello.", "Goodbye."]
    return _DIALOGS[idx % len(_DIALOGS)]


def _place_call_now() -> bool:
    """
    Attempt to place a call once, returning True if Twilio accepted the request.
    Sets 'outgoing pending' immediately to prevent duplicates before callbacks.
    Also preselects voice/dialog for the call.
    """
    client = _ensure_twilio_client()
    from_n = _choose_from_number()
    public_url = _runtime.public_base_url or ""
    if not client or not from_n or not public_url:
        return False
    try:
        _prepare_params_for_next_call()
        call = client.calls.create(
            to=_runtime.to_number,
            from_=from_n,
            url=f"{public_url}/voice",
            status_callback=f"{public_url}/status",
            status_callback_event=["initiated", "ringing", "answered", "completed"],
            status_callback_method="POST",
        )
        logging.info("Placed call: %s", getattr(call, "sid", "<sid>"))
        _note_attempt(time.time(), _runtime.to_number)
        _mark_outgoing_pending()
        return True
    except Exception as e:
        logging.error("Twilio call placement failed: %s", e)
        return False


def _initialize_schedule_if_needed(now: int) -> None:
    global _next_call_epoch_s, _interval_start_epoch_s, _interval_total_seconds
    with _next_call_epoch_s_lock:
        if _next_call_epoch_s is None:
            _interval_total_seconds = _compute_next_interval_seconds()
            _interval_start_epoch_s = now
            _next_call_epoch_s = now + int(_interval_total_seconds or 0)


def _reset_schedule_after_completion(now: int) -> None:
    global _next_call_epoch_s, _interval_start_epoch_s, _interval_total_seconds
    with _next_call_epoch_s_lock:
        interval = _compute_next_interval_seconds()
        _interval_total_seconds = interval
        _interval_start_epoch_s = now
        _next_call_epoch_s = now + int(interval)


def _dialer_loop() -> None:
    logging.info("Dialer thread started.")
    while not _stop_requested.is_set():
        now = int(time.time())
        _initialize_schedule_if_needed(now)

        # Manual request
        if _manual_call_requested.is_set():
            _manual_call_requested.clear()
            if _runtime.to_number:
                # Only consider "busy" when there is an actual active CallSid; ignore "pending" for manual path
                if (_get_current_call_sid() is None) and _within_active_window(_now_local()):
                    can, wait_s = _can_attempt(now, _runtime.to_number)
                    if can:
                        ok = _place_call_now()
                        if not ok:
                            _reset_schedule_after_completion(now)
                    else:
                        logging.info("Attempt capped; wait %s seconds.", wait_s)
                else:
                    logging.info("Call busy or outside active window; manual attempt suppressed.")
            else:
                logging.info("TO_NUMBER not configured; manual attempt ignored.")

        # Automatic schedule-based attempt
        with _next_call_epoch_s_lock:
            ready = (_next_call_epoch_s is not None and now >= _next_call_epoch_s)
        if ready and _runtime.to_number and not _is_call_busy() and _within_active_window(_now_local()):
            can, _ = _can_attempt(now, _runtime.to_number)
            if can:
                ok = _place_call_now()
                if not ok:
                    _reset_schedule_after_completion(now)
            else:
                _reset_schedule_after_completion(now)

        # Sleep in short steps for responsiveness on shutdown
        for _ in range(5):
            if _stop_requested.is_set():
                break
            time.sleep(0.2)

    logging.info("Dialer thread stopped.")


# Transcripts
_TRANSCRIPTS_LOCK = threading.Lock()
_TRANSCRIPTS: Dict[str, List[Dict[str, Any]]] = {}


def _append_transcript(call_sid: str, role: str, text: str, is_final: bool) -> None:
    if not text:
        return
    entry = {"t": time.time(), "role": role, "text": text, "final": bool(is_final)}
    with _TRANSCRIPTS_LOCK:
        _TRANSCRIPTS.setdefault(call_sid, []).append(entry)


# UI routes
@app.route("/")
def root():
    return redirect(url_for("scamcalls"))


@app.route("/scamcalls", methods=["GET"])
def scamcalls():
    return render_template("scamcalls.html", is_admin=_admin_authenticated())


# Admin auth
def _admin_defaults() -> Tuple[str, Optional[str], bool]:
    env_user = (_runtime.admin_user or "").strip() if _runtime.admin_user else None
    env_hash = (_runtime.admin_password_hash or "").strip() if _runtime.admin_password_hash else None
    if env_user and env_hash and bcrypt is not None:
        return env_user, env_hash, True
    return "bootycall", None, False


def _admin_authenticated() -> bool:
    return bool(session.get("is_admin") is True)


def _require_admin_for_api() -> Optional[Response]:
    if not _admin_authenticated():
        return Response(json.dumps({"error": "unauthorized"}), status=401, mimetype="application/json")
    return None


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        if _admin_authenticated():
            return redirect(url_for("scamcalls"))
        return render_template("admin_login.html", error=None)
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    effective_user, effective_hash, uses_hash = _admin_defaults()
    ok = False
    if uses_hash and effective_hash and bcrypt is not None:
        if username == effective_user:
            try:
                ok = bcrypt.checkpw(password.encode("utf-8"), effective_hash.encode("utf-8"))
            except Exception:
                ok = False
    else:
        ok = (username == effective_user and password == "scammers")
    if not ok:
        return render_template("admin_login.html", error="Invalid credentials.")
    session["is_admin"] = True
    return redirect(url_for("scamcalls"))


@app.route("/admin/logout", methods=["GET"])
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("scamcalls"))


# Admin env editor
@app.route("/api/admin/env", methods=["GET"])
def api_admin_env_get():
    resp = _require_admin_for_api()
    if resp:
        return resp
    editable = [{"key": k, "value": v} for (k, v) in _current_env_editable_pairs()]
    return jsonify({"editable": editable})


@app.route("/api/admin/env", methods=["POST"])
def api_admin_env_post():
    resp = _require_admin_for_api()
    if resp:
        return resp
    try:
        data = request.get_json(force=True, silent=False) or {}
        updates_raw = data.get("updates") or {}
        if not isinstance(updates_raw, dict):
            return Response("Invalid payload.", status=400)
        clean_updates: Dict[str, str] = {}
        for k, v in updates_raw.items():
            if k in _SECRET_ENV_KEYS:
                continue
            if k in _EDITABLE_ENV_KEYS:
                clean_updates[str(k)] = "" if v is None else str(v)
        _apply_env_updates(clean_updates)
        return jsonify({"ok": True})
    except Exception as e:
        logging.error("Failed to save env updates: %s", e)
        return Response("Failed to save settings.", status=500)


# Status API
@app.route("/api/status", methods=["GET"])
def api_status():
    now_i = int(time.time())
    with _next_call_epoch_s_lock:
        next_epoch = _next_call_epoch_s
        interval_start = _interval_start_epoch_s
        interval_total = _interval_total_seconds

    # Compute both pending and active, but expose "call_in_progress" only for a real active CallSid.
    # This keeps the UI accurate: it should not show "active call" when we are merely pending.
    _ = _is_outgoing_pending()  # retained for potential internal diagnostics
    active_sid = _get_current_call_sid()
    call_in_progress = bool(active_sid)

    within = _within_active_window(_now_local())
    to = _runtime.to_number
    attempts_last_hour = 0
    attempts_last_day = 0
    can_attempt = True
    wait_if_capped = 0
    if to:
        _prune_attempts(now_i, to)
        with _attempts_lock:
            lst = _dest_attempts.get(to, [])
            attempts_last_hour = len([t for t in lst if t >= now_i - 3600])
            attempts_last_day = len(lst)
        can_attempt, wait_if_capped = _can_attempt(now_i, to)

    seconds_until_next = None
    if not call_in_progress and next_epoch is not None:
        seconds_until_next = max(0, int(next_epoch - now_i))

    interval_elapsed = None
    if interval_start is not None and interval_total is not None:
        interval_elapsed = None if call_in_progress else max(0, now_i - interval_start)

    payload = {
        "now_epoch": now_i,
        "next_call_epoch": next_epoch,
        "seconds_until_next": seconds_until_next,
        "within_active_window": within,
        "active_hours_local": _runtime.active_hours_local,
        "active_days": _runtime.active_days,
        "attempts_last_hour": attempts_last_hour,
        "attempts_last_day": attempts_last_day,
        "hourly_max_attempts": _runtime.hourly_max_attempts,
        "daily_max_attempts": _runtime.daily_max_attempts,
        "can_attempt_now": can_attempt,
        "wait_seconds_if_capped": wait_if_capped,
        "interval_total_seconds": interval_total,
        "interval_elapsed_seconds": interval_elapsed,
        "to_number": _runtime.to_number,
        "from_number": _runtime.from_number,
        "from_numbers": _runtime.from_numbers,
        "call_in_progress": call_in_progress,
        "media_streams_enabled": bool(_runtime.enable_media_streams),
        "public_base_url": _runtime.public_base_url or "",
    }
    return jsonify(payload)


# Live transcript API
@app.route("/api/live", methods=["GET"])
def api_live_transcript():
    sid = _get_current_call_sid()
    with _TRANSCRIPTS_LOCK:
        transcript = list(_TRANSCRIPTS.get(sid or "", [])) if sid else []
    return jsonify({
        "ok": True,
        # Report in_progress only on an actual CallSid (not on "pending") to keep UI accurate.
        "in_progress": bool(sid),
        "callSid": sid or "",
        "transcript": transcript,
        "media_streams_enabled": bool(_runtime.enable_media_streams),
    })


# One-shot greeting setter
_ONE_SHOT_GREETING: Optional[str] = None
_ONE_SHOT_GREETING_LOCK = threading.Lock()


def _pop_one_shot_opening() -> Optional[str]:
    global _ONE_SHOT_GREETING
    with _ONE_SHOT_GREETING_LOCK:
        val = _ONE_SHOT_GREETING
        _ONE_SHOT_GREETING = None
        return val


@app.route("/api/next-greeting", methods=["POST"])
def api_next_greeting():
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    phrase = (data.get("phrase") or "").strip()
    words = [w for w in re.split(r"\s+", phrase) if w]
    if not (5 <= len(words) <= 15):
        return Response("Phrase must be between 5 and 15 words.", status=400)
    global _ONE_SHOT_GREETING
    with _ONE_SHOT_GREETING_LOCK:
        _ONE_SHOT_GREETING = phrase
    return jsonify(ok=True)


def _build_opening_lines_for_sid(call_sid: str) -> List[str]:
    """
    Build opening lines for this call. If a one-shot greeting is present, use that.
    Otherwise, use the first line from the selected dialog for this call.
    Optionally append company/topic context.
    """
    one = _pop_one_shot_opening()
    if one:
        lines = [one]
    else:
        params = _get_params_for_sid(call_sid)
        base_dialog = _get_dialog_lines(params.dialog_idx)
        first = base_dialog[0] if base_dialog else "Hello."
        lines = [first]
    # Optional context additions
    if _runtime.company_name:
        lines.append(f"This is {_runtime.company_name}.")
    if _runtime.topic:
        lines.append(f"I am calling about {_runtime.topic}.")
    return [ln for ln in lines if ln]


# Twilio voice routes
@app.route("/voice", methods=["POST", "GET"])
def voice_entrypoint():
    """
    Entry point for the call.
    Behavior: Wait for the callee to speak first, then the assistant responds.
    """
    if VoiceResponse is None:
        return Response("Server missing Twilio TwiML library.", status=500)
    vr = VoiceResponse()

    call_sid = request.values.get("CallSid", "") or None
    if call_sid:
        _set_current_call_sid(call_sid)
        _clear_outgoing_pending()
        _assign_params_to_sid(call_sid)

    # Optional Media Streams
    if _runtime.enable_media_streams and Start is not None and Stream is not None and _runtime.public_base_url:
        try:
            start = Start()
            ws_base = _runtime.public_base_url.replace("http:", "ws:").replace("https:", "wss:")
            start.stream(url=f"{ws_base}/media-in", track="inbound_track")
            start.stream(url=f"{ws_base}/media-out", track="outbound_track")
            vr.append(start)
        except Exception as e:
            logging.warning("Failed to attach media streams: %s", e)

    # Wait for callee to speak first
    g = Gather(
        input="speech",
        method="POST",
        action=url_for("hello_got_speech", _external=True),
        timeout=str(_runtime.callee_silence_hangup_seconds),
        speech_timeout="auto",
        barge_in=False,
        partial_result_callback=url_for("transcribe_partial", stage="hello", seq=0, _external=True),
        partial_result_callback_method="POST",
        language=_runtime.tts_language,
    )
    # No initial speech from assistant; we are waiting for the callee
    vr.append(g)

    # In case the gather times out and Twilio falls through, provide a fallback redirect to action
    vr.redirect(url_for("hello_got_speech", _external=True), method="POST")
    return Response(str(vr), status=200, mimetype="text/xml")


@app.route("/hello", methods=["POST"])
def hello_got_speech():
    """
    Called after the initial Gather when the callee speaks (or on timeout via redirect).
    Respond with opening lines, then listen again.
    """
    if VoiceResponse is None:
        return Response("Server missing Twilio TwiML library.", status=500)
    vr = VoiceResponse()

    call_sid = request.values.get("CallSid", "") or ""
    if call_sid:
        _set_current_call_sid(call_sid)
        _clear_outgoing_pending()
        _assign_params_to_sid(call_sid)

    # Record what callee said (if any)
    speech_text = (request.values.get("SpeechResult") or "").strip()
    if speech_text:
        _append_transcript(call_sid, "Callee", speech_text, is_final=True)

    # Assistant speaks opening lines now
    params = _get_params_for_sid(call_sid)
    opening_lines = _build_opening_lines_for_sid(call_sid)
    for i, line in enumerate(opening_lines):
        _append_transcript(call_sid, "Assistant", line, is_final=True)
        vr.say(line, voice=params.voice, language=_runtime.tts_language)
        if i < len(opening_lines) - 1:
            vr.pause(length=1)

    # Now listen again for callee's response and continue in /transcribe
    g = Gather(
        input="speech",
        method="POST",
        action=url_for("transcribe", seq=1, _external=True),
        timeout=str(_runtime.callee_silence_hangup_seconds),
        speech_timeout="auto",
        barge_in=True,
        partial_result_callback=url_for("transcribe_partial", stage="dialog", seq=1, _external=True),
        partial_result_callback_method="POST",
        language=_runtime.tts_language,
    )
    vr.append(g)
    # If no response, politely end the call
    vr.say("Goodbye.", voice=params.voice, language=_runtime.tts_language)
    vr.hangup()
    return Response(str(vr), status=200, mimetype="text/xml")


@app.route("/transcribe", methods=["POST"])
def transcribe():
    if VoiceResponse is None:
        return Response("Server missing Twilio TwiML library.", status=500)
    call_sid = request.values.get("CallSid", "") or ""
    _set_current_call_sid(call_sid or _get_current_call_sid())
    speech_text = (request.values.get("SpeechResult") or "").strip()
    if speech_text:
        _append_transcript(call_sid, "Callee", speech_text, is_final=True)

    # Assistant responds with the next line from the dialog, then hang up
    params = _get_params_for_sid(call_sid)
    dialog_lines = _get_dialog_lines(params.dialog_idx)
    reply = dialog_lines[1] if len(dialog_lines) > 1 else "Goodbye."
    _append_transcript(call_sid, "Assistant", reply, is_final=True)

    vr = VoiceResponse()
    vr.say(reply, voice=params.voice, language=_runtime.tts_language)
    vr.hangup()
    return Response(str(vr), status=200, mimetype="text/xml")


@app.route("/transcribe-partial", methods=["POST"])
def transcribe_partial():
    call_sid = request.values.get("CallSid", "") or ""
    _set_current_call_sid(call_sid or _get_current_call_sid())
    part = (request.values.get("UnstableSpeechResult") or request.values.get("SpeechResult") or "").strip()
    if part:
        _append_transcript(call_sid, "Callee", part, is_final=False)
    return ("", 204)


@app.route("/status", methods=["POST"])
def status_callback():
    """
    Twilio status callback: initiated, ringing, answered, completed.
    Used to toggle 'call_in_progress' and to reset the schedule after completion.
    """
    call_sid = request.values.get("CallSid", "") or ""
    call_status = (request.values.get("CallStatus") or "").lower()
    answered_by = request.values.get("AnsweredBy") or ""
    sip_code = request.values.get("SipResponseCode") or ""
    duration = request.values.get("CallDuration") or ""

    logging.info(
        "Status cb: sid=%s status=%s answered_by=%s sip=%s duration=%s",
        call_sid,
        call_status,
        answered_by,
        sip_code,
        duration,
    )

    now = int(time.time())

    if call_status in ("initiated", "ringing", "in-progress", "answered"):
        if call_sid:
            _set_current_call_sid(call_sid)
        _clear_outgoing_pending()

    if call_status == "completed":
        _set_current_call_sid(None)
        _clear_outgoing_pending()
        _reset_schedule_after_completion(now)

    return ("", 204)


# Media Streams bridge to browser
if Sock is not None:
    _sock = Sock(app)
else:
    _sock = None

_AUDIO_CLIENTS_LOCK = threading.Lock()
_AUDIO_CLIENTS: Set[Any] = set()


def _broadcast_audio(payload_b64: str) -> None:
    if not payload_b64:
        return
    with _AUDIO_CLIENTS_LOCK:
        clients = list(_AUDIO_CLIENTS)
    for ws in clients:
        try:
            ws.send(payload_b64)
        except Exception:
            try:
                with _AUDIO_CLIENTS_LOCK:
                    _AUDIO_CLIENTS.discard(ws)
            except Exception:
                pass


if _sock is not None:
    @_sock.route("/media-in")
    def media_in(ws):  # type: ignore
        try:
            while True:
                msg = ws.receive()
                if msg is None:
                    break
                try:
                    data = json.loads(msg)
                except Exception:
                    continue
                if data.get("event") == "media":
                    payload = data.get("media", {}).get("payload", "")
                    if payload:
                        _broadcast_audio(payload)
        except Exception:
            pass

    @_sock.route("/media-out")
    def media_out(ws):  # type: ignore
        try:
            while True:
                msg = ws.receive()
                if msg is None:
                    break
        except Exception:
            pass

    @_sock.route("/client-audio")
    def client_audio(ws):  # type: ignore
        with _AUDIO_CLIENTS_LOCK:
            _AUDIO_CLIENTS.add(ws)
        try:
            while True:
                msg = ws.receive()
                if msg is None:
                    break
        except Exception:
            pass
        finally:
            with _AUDIO_CLIENTS_LOCK:
                _AUDIO_CLIENTS.discard(ws)


# Ngrok management
_active_tunnel_url: Optional[str] = None


def _start_ngrok_if_enabled() -> None:
    global _active_tunnel_url
    if not _runtime.use_ngrok:
        return
    if ngrok_lib is None:
        logging.warning("USE_NGROK=true but pyngrok is not installed. Skipping.")
        return
    try:
        if _active_tunnel_url:
            return
        port = _runtime.flask_port or 8080
        tun = ngrok_lib.connect(addr=port, proto="http")
        _active_tunnel_url = tun.public_url  # type: ignore
        os.environ["PUBLIC_BASE_URL"] = _active_tunnel_url
        _runtime.public_base_url = _active_tunnel_url
        logging.info("ngrok tunnel active at %s", _active_tunnel_url)
    except Exception as e:
        logging.error("Failed to start ngrok: %s", e)


@atexit.register
def _shutdown_ngrok():
    try:
        if ngrok_lib is not None:
            ngrok_lib.kill()
    except Exception:
        pass


def _handle_termination(signum, frame):
    """
    Handle SIGINT/SIGTERM: stop background tasks and exit the process.
    """
    logging.info("Termination signal received (%s). Stopping service.", signum)
    try:
        _stop_requested.set()
    except Exception:
        pass
    # Give background threads a brief moment to exit, then terminate process
    try:
        time.sleep(0.5)
    except Exception:
        pass
    raise SystemExit(0)


signal.signal(signal.SIGTERM, _handle_termination)
signal.signal(signal.SIGINT, _handle_termination)


def _start_background_threads() -> None:
    global _dialer_thread
    if _dialer_thread is None or not _dialer_thread.is_alive():
        _dialer_thread = threading.Thread(target=_dialer_loop, name="dialer-thread", daemon=True)
        _dialer_thread.start()


@app.route("/api/call-now", methods=["POST"])
def api_call_now():
    if not _within_active_window(_now_local()):
        return jsonify(ok=False, reason="outside_active_window", message="Outside active calling window."), 200
    if not _runtime.to_number:
        return jsonify(ok=False, reason="missing_destination", message="TO_NUMBER is not configured."), 400
    now = int(time.time())
    allowed, wait_s = _can_attempt(now, _runtime.to_number)
    if not allowed:
        return jsonify(ok=False, reason="cap_reached", wait_seconds=wait_s), 429
    # If an actual call is in progress, block; pending alone should not block the request itself.
    if _get_current_call_sid() is not None:
        return jsonify(ok=False, reason="already_in_progress", message="A call is already in progress."), 409
    _mark_outgoing_pending()  # reflect pending immediately to prevent scheduler overlap before callbacks
    _manual_call_requested.set()
    return jsonify(ok=True)


def main():
    logging.info("Scam Call Console starting.")
    _start_ngrok_if_enabled()
    _start_background_threads()
    host = _runtime.flask_host or os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(_runtime.flask_port or _parse_int(os.environ.get("FLASK_PORT"), 8080))
    debug = bool(_runtime.flask_debug or _parse_bool(os.environ.get("FLASK_DEBUG"), False))
    # use_reloader=False prevents duplicate processes that ignore signals
    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    main()
