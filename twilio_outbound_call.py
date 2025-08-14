#!/usr/bin/env python3
"""
Scam Call Console: Outbound caller service with admin UI, pacing, Twilio voice,
optional Media Streams, live transcript API, history APIs, and clean shutdown.

Diagnostic build: adds comprehensive logging for call placement, scheduling,
request handling, Twilio callbacks, env updates, and live audio streaming.

Notes:
- Do not store real secrets in source control; keep .env private.
- Phone numbers and SIDs are masked in logs to reduce exposure.
- All logs go to stdout using Python logging.
"""

from __future__ import annotations

import atexit
import base64
import json
import logging
import os
import random
import re
import signal
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse

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

# Optional rotating prompts used for professional follow-ups
try:
    from rotating_iv_prompts import PROMPTS as IV_PROMPTS  # type: ignore
except Exception:
    IV_PROMPTS = []  # type: ignore


# ---------- Logging setup ----------
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(threadName)s] %(name)s:%(lineno)d %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("scam_call_console")


def _mask_phone(val: Optional[str]) -> str:
    s = (val or "").strip()
    if not s:
        return ""
    digits = "".join(ch for ch in s if ch.isdigit() or ch == "+")
    if len(digits) <= 4:
        return f"...{digits}"
    return f"...{digits[-4:]}"


def _mask_sid(sid: Optional[str]) -> str:
    s = (sid or "").strip()
    if len(s) <= 6:
        return s
    return f"{s[:4]}...{s[-4:]}"


app = Flask(__name__, static_folder="static", template_folder="templates")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)  # type: ignore
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(32))


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
        log.error("Failed to read .env pairs: %s", e)
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
    max_dialog_turns: int = 6
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
    _runtime.max_dialog_turns = max(0, _parse_int(os.environ.get("MAX_DIALOG_TURNS"), 6))

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
    "MAX_DIALOG_TURNS",
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
    "DIRECT_DIAL_ON_TRIGGER",
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
        log.info("Wrote .env updates for keys: %s", ", ".join(sorted(updates.keys())))
    except Exception as e:
        log.error("Failed writing .env: %s", e)


def _apply_env_updates(updates: Dict[str, str]) -> None:
    log.info("Applying env updates: %s", {k: ("<redacted>" if k in _SECRET_ENV_KEYS else updates[k]) for k in updates})
    _write_env_updates_preserving_comments(updates)
    for k, v in updates.items():
        if k in _EDITABLE_ENV_KEYS and k not in _SECRET_ENV_KEYS:
            os.environ[k] = "" if v is None else str(v)
    _load_runtime_from_env()
    _log_runtime_summary(context="after env update")


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
    log.info("Noted attempt at %s for %s", int(now_ts), _mask_phone(to_number))


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
            wait = max(1, (int(oldest) + 3600) - now_ts)
            log.info("Attempt blocked by hourly cap: %s/%s, wait %ss", len(last_hour), _runtime.hourly_max_attempts, wait)
            return False, wait
        if len(lst) >= _runtime.daily_max_attempts:
            log.info("Attempt blocked by daily cap: %s/%s", len(lst), _runtime.daily_max_attempts)
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
        log.error("Twilio SDK not available. Install with: pip install twilio")
        return None
    sid = os.environ.get("TWILIO_ACCOUNT_SID")
    tok = os.environ.get("TWILIO_AUTH_TOKEN")
    if not sid or not tok:
        log.error("Missing TWILIO_ACCOUNT_SID or TWILIO_AUTH_TOKEN in environment.")
        return None
    _twilio_client = Client(sid, tok)
    log.info("Twilio client initialized (account SID present).")
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
_PENDING_TTL_SECONDS = 30.0  # use short TTL during diagnostics


def _set_current_call_sid(sid: Optional[str]) -> None:
    global _CURRENT_CALL_SID
    with _CURRENT_CALL_LOCK:
        _CURRENT_CALL_SID = sid
    log.info("Set current call SID to %s", _mask_sid(sid))


def _get_current_call_sid() -> Optional[str]:
    with _CURRENT_CALL_LOCK:
        return _CURRENT_CALL_SID


def _mark_outgoing_pending() -> None:
    global _PENDING_UNTIL_TS
    with _PENDING_LOCK:
        _PENDING_UNTIL_TS = time.time() + _PENDING_TTL_SECONDS
    log.info("Marked outgoing call as pending for %.0fs", _PENDING_TTL_SECONDS)


def _clear_outgoing_pending() -> None:
    global _PENDING_UNTIL_TS
    with _PENDING_LOCK:
        _PENDING_UNTIL_TS = None
    log.info("Cleared outgoing pending flag.")


def _is_outgoing_pending() -> bool:
    global _PENDING_UNTIL_TS
    with _PENDING_LOCK:
        if _PENDING_UNTIL_TS is None:
            return False
        if time.time() >= _PENDING_UNTIL_TS:
            _PENDING_UNTIL_TS = None
            log.info("Pending flag expired.")
            return False
        return True


def _busy_reason() -> Optional[str]:
    if _get_current_call_sid() is not None:
        return "current_call_sid_set"
    if _is_outgoing_pending():
        return "outgoing_pending"
    return None


# Dialog rotation and per-call parameters
@dataclass
class CallParams:
    voice: str
    dialog_idx: int


# Dialog sets (2-line seed; follow-ups come from rotating_iv_prompts when available).
_DIALOGS: List[List[str]] = [
    ["Where is my refund?", "I need a straight answer."],
    ["Let us skip delays.", "Please be direct."],
    ["I expect clarity.", "Provide specifics now."],
    ["Avoid generalities.", "Focus on the facts."],
    ["Please explain the status.", "Outline next steps clearly."],
    ["Confirm the details.", "Do not omit anything relevant."],
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
        voice = "man" if (_PLACED_CALL_COUNT % 2 == 1) else "woman"
        _LAST_DIALOG_IDX = (_LAST_DIALOG_IDX + 1) % max(1, len(_DIALOGS))
        log.info("Selected call params: voice=%s, dialog_idx=%s", voice, _LAST_DIALOG_IDX)
        return CallParams(voice=voice, dialog_idx=_LAST_DIALOG_IDX)


def _prepare_params_for_next_call() -> None:
    global _PENDING_CALL_PARAMS
    with _PARAMS_LOCK:
        _PENDING_CALL_PARAMS = _select_next_call_params()
    log.info("Prepared params for next call: %s", _PENDING_CALL_PARAMS)


def _assign_params_to_sid(sid: str) -> None:
    global _PENDING_CALL_PARAMS
    if not sid:
        return
    with _PARAMS_LOCK:
        if _PENDING_CALL_PARAMS is None:
            _PENDING_CALL_PARAMS = _select_next_call_params()
        _CALL_PARAMS_BY_SID[sid] = _PENDING_CALL_PARAMS
        log.info("Assigned params to SID %s: %s", _mask_sid(sid), _PENDING_CALL_PARAMS)
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


def _should_record_call() -> bool:
    mode = (_runtime.recording_mode or "off").lower()
    if mode != "on":
        return False
    if _runtime.recording_jurisdiction_mode == "disable_in_two_party":
        return False
    return True


def _compose_followup_prompts(turn_seed: int) -> List[str]:
    if _runtime.rotate_prompts and IV_PROMPTS:
        idx = abs(turn_seed) % len(IV_PROMPTS)
        try:
            text = IV_PROMPTS[idx].format(
                company_name=_runtime.company_name or "",
                topic=_runtime.topic or "the topic",
            )
        except Exception:
            text = IV_PROMPTS[idx]
        parts = [p.strip() for p in text.split("||") if p.strip()]
        return parts[:2] if parts else ["Could you elaborate?", "What details can you provide?"]
    return ["Could you clarify?", "What details can you share?"]


def _compose_assistant_reply(call_sid: str, turn: int) -> List[str]:
    params = _get_params_for_sid(call_sid)
    if turn <= 1:
        dialog_lines = _get_dialog_lines(params.dialog_idx)
        reply = dialog_lines[1] if len(dialog_lines) > 1 else "Please continue."
        return [reply]
    seed = params.dialog_idx + turn
    return _compose_followup_prompts(seed)


def _public_url_warnings(url: Optional[str]) -> List[str]:
    warnings: List[str] = []
    if not url:
        warnings.append("missing_public_base_url")
        return warnings
    try:
        u = urlparse(url)
        host = (u.hostname or "").lower()
        if host in ("localhost", "127.0.0.1"):
            warnings.append("public_base_url_is_localhost")
        if host.startswith("192.168.") or host.startswith("10.") or host.startswith("172.16.") or host.startswith("172.17.") or host.startswith("172.18.") or host.startswith("172.19.") or host.startswith("172.2") or host.startswith("172.3"):
            warnings.append("public_base_url_is_private_lan")
        if not u.scheme or u.scheme not in ("http", "https"):
            warnings.append("public_base_url_invalid_scheme")
    except Exception:
        warnings.append("public_base_url_parse_error")
    return warnings


def _diagnostics_ready_to_call() -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if not _runtime.to_number:
        reasons.append("missing_to_number")
    from_n = _choose_from_number()
    if not from_n:
        reasons.append("missing_from_number")
    if _ensure_twilio_client() is None:
        reasons.append("twilio_client_not_initialized")
    warnings = _public_url_warnings(_runtime.public_base_url)
    if warnings:
        reasons.extend(warnings)
    # We are "ready" if only warnings exist (e.g., private URL), as we still want to test-call.
    fatal = [r for r in reasons if r in ("missing_to_number", "missing_from_number", "twilio_client_not_initialized")]
    return (len(fatal) == 0), reasons


def _place_call_now() -> bool:
    client = _ensure_twilio_client()
    from_n = _choose_from_number()
    public_url = _runtime.public_base_url or ""
    to_n = _runtime.to_number

    if not client:
        log.error("Cannot place call: Twilio client missing.")
        return False
    if not to_n:
        log.error("Cannot place call: TO_NUMBER is not configured.")
        return False
    if not from_n:
        log.error("Cannot place call: FROM_NUMBER or FROM_NUMBERS is not configured.")
        return False
    if not public_url:
        log.error("Cannot place call: PUBLIC_BASE_URL is not set.")
        return False

    # Warn loudly if URL appears private
    url_warn = _public_url_warnings(public_url)
    if url_warn:
        log.warning("PUBLIC_BASE_URL warnings: %s (value=%s)", url_warn, public_url)

    try:
        log.info("Preparing to place call (preflight). to=%s from=%s base=%s", _mask_phone(to_n), _mask_phone(from_n), public_url)
        _prepare_params_for_next_call()
        kwargs: Dict[str, Any] = dict(
            to=to_n,
            from_=from_n,
            url=f"{public_url}/voice",
            status_callback=f"{public_url}/status",
            status_callback_event=["initiated", "ringing", "answered", "completed"],
            status_callback_method="POST",
        )
        if _should_record_call():
            kwargs.update({
                "record": True,
                "recording_status_callback": f"{public_url}/recording-status",
                "recording_status_callback_event": ["in-progress", "completed"],
                "recording_status_callback_method": "POST",
            })
        log.info(
            "Placing call via Twilio API. to=%s from=%s twiml_url=%s status_cb=%s",
            _mask_phone(kwargs["to"]),
            _mask_phone(kwargs["from_"]),
            kwargs["url"],
            kwargs["status_callback"],
        )
        call = client.calls.create(**kwargs)  # type: ignore
        sid = getattr(call, "sid", "") or ""
        log.info("Twilio accepted call. CallSid=%s", _mask_sid(sid) or "<none>")
        _note_attempt(time.time(), to_n)
        _mark_outgoing_pending()
        if sid:
            _assign_params_to_sid(sid)
            _init_call_meta_if_absent(sid, to=to_n, from_n=from_n, started_at=int(time.time()))
        return True
    except Exception as e:
        log.exception("Twilio call placement failed: %s", e)
        return False


def _initialize_schedule_if_needed(now: int) -> None:
    global _next_call_epoch_s, _interval_start_epoch_s, _interval_total_seconds
    with _next_call_epoch_s_lock:
        if _next_call_epoch_s is None:
            _interval_total_seconds = _compute_next_interval_seconds()
            _interval_start_epoch_s = now
            _next_call_epoch_s = now + int(_interval_total_seconds or 0)
            log.info(
                "Initialized schedule: next_call_epoch=%s (in %ss), interval_total=%ss",
                _next_call_epoch_s,
                (_next_call_epoch_s - now) if _next_call_epoch_s else None,
                _interval_total_seconds,
            )


def _reset_schedule_after_completion(now: int) -> None:
    global _next_call_epoch_s, _interval_start_epoch_s, _interval_total_seconds
    with _next_call_epoch_s_lock:
        interval = _compute_next_interval_seconds()
        prev_next = _next_call_epoch_s
        _interval_total_seconds = interval
        _interval_start_epoch_s = now
        _next_call_epoch_s = now + int(interval)
        log.info(
            "Reset schedule after completion: prev_next=%s, new_next=%s (in %ss), interval_total=%ss",
            prev_next,
            _next_call_epoch_s,
            (_next_call_epoch_s - now) if _next_call_epoch_s else None,
            _interval_total_seconds,
        )


def _log_dialer_gates(label: str) -> Dict[str, Any]:
    now_ts = int(time.time())
    active_sid = _get_current_call_sid()
    pending = _is_outgoing_pending()
    within = _within_active_window(_now_local())
    ready, reasons = _diagnostics_ready_to_call()
    can_now, wait_s = (True, 0)
    if _runtime.to_number:
        can_now, wait_s = _can_attempt(now_ts, _runtime.to_number)
    snapshot = dict(
        label=label,
        active_sid_set=bool(active_sid),
        pending=pending,
        within_active_window=within,
        ready=ready,
        reasons=reasons,
        can_attempt=can_now,
        wait_if_capped=wait_s,
        to=_mask_phone(_runtime.to_number),
        from_single=_mask_phone(_runtime.from_number),
        from_pool_count=len(_runtime.from_numbers or []),
        public_url_set=bool(_runtime.public_base_url),
    )
    log.info("Dialer gates [%s]: %s", label, snapshot)
    return snapshot


def _dialer_loop() -> None:
    log.info("Dialer thread started.")
    while not _stop_requested.is_set():
        try:
            now = int(time.time())
            _initialize_schedule_if_needed(now)

            # Manual request (from /api/call-now if not direct-dial)
            if _manual_call_requested.is_set():
                _manual_call_requested.clear()
                log.info("Manual call request received by dialer.")
                gates = _log_dialer_gates("manual")
                if not gates["ready"]:
                    log.error("Manual call suppressed; not ready: %s", gates["reasons"])
                else:
                    if (not gates["active_sid_set"]) and gates["within_active_window"]:
                        if gates["can_attempt"]:
                            log.info("Manual dialer path proceeding to place call now.")
                            ok = _place_call_now()
                            log.info("Manual dialer path place_call_now result=%s", ok)
                            if not ok:
                                log.error("Manual call attempt failed. Rescheduling.")
                                _reset_schedule_after_completion(now)
                        else:
                            log.info("Manual attempt blocked by caps; wait %s seconds.", gates["wait_if_capped"])
                    else:
                        log.info("Manual attempt suppressed; active_sid=%s within_window=%s", gates["active_sid_set"], gates["within_active_window"])

            # Automatic schedule-based attempt
            with _next_call_epoch_s_lock:
                ready_time = (_next_call_epoch_s is not None and now >= _next_call_epoch_s)
                seconds_until = max(0, (_next_call_epoch_s - now)) if _next_call_epoch_s else None

            if ready_time:
                log.info("Schedule window reached. seconds_until_next=%s", seconds_until)
                gates = _log_dialer_gates("scheduled")
                if not gates["ready"]:
                    log.error("Scheduled attempt suppressed; not ready: %s", gates["reasons"])
                    _reset_schedule_after_completion(now)
                elif gates["pending"]:
                    log.info("Scheduled attempt suppressed; reason=outgoing_pending")
                    _reset_schedule_after_completion(now)  # do not tight-loop on pending
                elif gates["active_sid_set"]:
                    log.info("Scheduled attempt suppressed; reason=current_call_in_progress sid=%s", _mask_sid(_get_current_call_sid()))
                    _reset_schedule_after_completion(now)
                elif not gates["within_active_window"]:
                    log.info("Scheduled attempt suppressed; reason=outside_active_window")
                    _reset_schedule_after_completion(now)
                else:
                    if gates["can_attempt"]:
                        log.info("Scheduled dialer proceeding to place call now.")
                        ok = _place_call_now()
                        log.info("Scheduled dialer place_call_now result=%s", ok)
                        if not ok:
                            log.error("Scheduled call attempt failed. Rescheduling.")
                            _reset_schedule_after_completion(now)
                    else:
                        log.info("Scheduled attempt blocked by caps; rescheduling. wait=%s", gates["wait_if_capped"])
                        _reset_schedule_after_completion(now)

            # Sleep in short steps for responsiveness on shutdown
            for _ in range(5):
                if _stop_requested.is_set():
                    break
                time.sleep(0.2)
        except Exception as e:
            log.exception("Dialer loop error: %s", e)
            time.sleep(0.5)

    log.info("Dialer thread stopped.")


# Transcripts and call metadata
_TRANSCRIPTS_LOCK = threading.Lock()
_TRANSCRIPTS: Dict[str, List[Dict[str, Any]]] = {}

_CALL_META_LOCK = threading.Lock()
_CALL_META: Dict[str, Dict[str, Any]] = {}

HISTORY_DIR = Path("data/history")
HISTORY_DIR.mkdir(parents=True, exist_ok=True)


def _append_transcript(call_sid: str, role: str, text: str, is_final: bool) -> None:
    if not text:
        return
    entry = {"t": time.time(), "role": role, "text": text, "final": bool(is_final)}
    with _TRANSCRIPTS_LOCK:
        _TRANSCRIPTS.setdefault(call_sid, []).append(entry)
    log.debug("Transcript appended (%s): role=%s, final=%s, len(text)=%s", _mask_sid(call_sid), role, is_final, len(text))


def _init_call_meta_if_absent(sid: str, **kwargs: Any) -> None:
    with _CALL_META_LOCK:
        meta = _CALL_META.get(sid)
        if meta is None:
            meta = {}
            _CALL_META[sid] = meta
        for k, v in kwargs.items():
            if k not in meta or meta.get(k) in (None, "", 0):
                meta[k] = v
    log.debug("Initialized call meta if absent for %s with keys=%s", _mask_sid(sid), list(kwargs.keys()))


def _persist_call_history(sid: str) -> None:
    with _CALL_META_LOCK:
        meta = dict(_CALL_META.get(sid, {}))
    with _TRANSCRIPTS_LOCK:
        transcript = list(_TRANSCRIPTS.get(sid, []))
    if not sid:
        return
    try:
        payload = {
            "sid": sid,
            "meta": meta,
            "transcript": transcript,
        }
        p = HISTORY_DIR / f"{sid}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        log.info("Persisted call history for %s (%s entries).", _mask_sid(sid), len(transcript))
    except Exception as e:
        log.error("Failed to persist call history: %s", e)


def _load_call_history(sid: str) -> Optional[Dict[str, Any]]:
    p = HISTORY_DIR / f"{sid}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _scan_history_summaries(limit: int = 200) -> List[Dict[str, Any]]:
    items: List[Tuple[float, Path]] = []
    try:
        for f in HISTORY_DIR.glob("*.json"):
            try:
                items.append((f.stat().st_mtime, f))
            except Exception:
                continue
    except Exception:
        return []
    items.sort(key=lambda t: t[0], reverse=True)
    out: List[Dict[str, Any]] = []
    for _, f in items[:limit]:
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            meta = d.get("meta", {}) or {}
            out.append({
                "sid": d.get("sid", ""),
                "started_at": meta.get("started_at"),
                "completed_at": meta.get("completed_at"),
                "to": meta.get("to"),
                "from": meta.get("from"),
                "duration_seconds": meta.get("duration_seconds"),
                "has_recordings": bool(meta.get("recordings")),
            })
        except Exception:
            continue
    return out


def _log_runtime_summary(context: str = "startup") -> None:
    ready, reasons = _diagnostics_ready_to_call()
    log.info(
        "Runtime summary (%s): to=%s, from_single=%s, from_pool=%s, public_url_set=%s, "
        "active_hours=%s on %s, interval=%ss..%ss, caps(hour/day)=%s/%s, rotate_prompts=%s, "
        "media_streams=%s, use_ngrok=%s, ready_to_call=%s, reasons=%s",
        context,
        _mask_phone(_runtime.to_number),
        _mask_phone(_runtime.from_number),
        ",".join(_mask_phone(n) for n in _runtime.from_numbers) or "-",
        bool(_runtime.public_base_url),
        _runtime.active_hours_local,
        ",".join(_runtime.active_days),
        _runtime.min_interval_seconds,
        _runtime.max_interval_seconds,
        _runtime.hourly_max_attempts,
        _runtime.daily_max_attempts,
        _runtime.rotate_prompts,
        _runtime.enable_media_streams,
        _runtime.use_ngrok,
        ready,
        reasons,
    )


# UI routes
@app.route("/")
def root():
    log.info("GET / -> redirect to /scamcalls")
    return redirect(url_for("scamcalls"))


@app.route("/scamcalls", methods=["GET"])
def scamcalls():
    log.info("GET /scamcalls (admin=%s)", _admin_authenticated())
    return render_template("scamcalls.html", is_admin=_admin_authenticated())


@app.route("/scamcalls/history", methods=["GET"])
def scamcalls_history():
    log.info("GET /scamcalls/history")
    return render_template("history.html")


# Admin auth
def _admin_defaults() -> Tuple[str, Optional[str], bool]:
    env_user = (os.environ.get("ADMIN_USER") or "").strip() or (_runtime.admin_user or "").strip() if _runtime.admin_user else None
    env_hash = (os.environ.get("ADMIN_PASSWORD_HASH") or "").strip() or (_runtime.admin_password_hash or "").strip() if _runtime.admin_password_hash else None
    if env_user and env_hash and bcrypt is not None:
        return env_user, env_hash, True
    return "bootycall", None, False


def _admin_authenticated() -> bool:
    return bool(session.get("is_admin") is True)


def _require_admin_for_api() -> Optional[Response]:
    if not _admin_authenticated():
        log.warning("Admin API unauthorized access attempt.")
        return Response(json.dumps({"error": "unauthorized"}), status=401, mimetype="application/json")
    return None


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        if _admin_authenticated():
            log.info("GET /admin/login: already authenticated -> redirect")
            return redirect(url_for("scamcalls"))
        log.info("GET /admin/login: render login page")
        return render_template("admin_login.html", error=None)
    username = (request.form.get("username") or "").strip()
    # Do not log password
    effective_user, effective_hash, uses_hash = _admin_defaults()
    ok = False
    if uses_hash and effective_hash and bcrypt is not None:
        if username == effective_user:
            try:
                ok = bcrypt.checkpw((request.form.get("password") or "").encode("utf-8"), effective_hash.encode("utf-8"))
            except Exception:
                ok = False
    else:
        ok = (username == effective_user and (request.form.get("password") or "") == "scammers")
    log.info("POST /admin/login: user=%s, success=%s, uses_hash=%s", username, ok, uses_hash)
    if not ok:
        return render_template("admin_login.html", error="Invalid credentials.")
    session["is_admin"] = True
    return redirect(url_for("scamcalls"))


@app.route("/admin/logout", methods=["GET"])
def admin_logout():
    log.info("GET /admin/logout")
    session.pop("is_admin", None)
    return redirect(url_for("scamcalls"))


# Admin env editor
@app.route("/api/admin/env", methods=["GET"])
def api_admin_env_get():
    resp = _require_admin_for_api()
    if resp:
        return resp
    editable = [{"key": k, "value": v} for (k, v) in _current_env_editable_pairs()]
    log.info("GET /api/admin/env -> %s keys", len(editable))
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
            log.error("POST /api/admin/env invalid payload type.")
            return Response("Invalid payload.", status=400)
        clean_updates: Dict[str, str] = {}
        for k, v in updates_raw.items():
            if k in _SECRET_ENV_KEYS:
                continue
            if k in _EDITABLE_ENV_KEYS:
                clean_updates[str(k)] = "" if v is None else str(v)
        log.info("POST /api/admin/env applying %s updates.", len(clean_updates))
        _apply_env_updates(clean_updates)
        return jsonify({"ok": True})
    except Exception as e:
        log.exception("Failed to save env updates: %s", e)
        return Response("Failed to save settings.", status=500)


# Status API
@app.route("/api/status", methods=["GET"])
def api_status():
    now_i = int(time.time())
    with _next_call_epoch_s_lock:
        next_epoch = _next_call_epoch_s
        interval_start = _interval_start_epoch_s
        interval_total = _interval_total_seconds

    pend = _is_outgoing_pending()
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

    ready, reasons = _diagnostics_ready_to_call()

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
        "outgoing_pending": pend,
        "media_streams_enabled": bool(_runtime.enable_media_streams),
        "public_base_url": _runtime.public_base_url or "",
        "ready_to_call": ready,
        "not_ready_reasons": reasons,
    }
    log.debug(
        "GET /api/status -> in_progress=%s, seconds_until_next=%s, pending=%s, ready=%s, reasons=%s",
        call_in_progress, seconds_until_next, pend, ready, reasons
    )
    return jsonify(payload)


# Live transcript API
@app.route("/api/live", methods=["GET"])
def api_live_transcript():
    sid = _get_current_call_sid()
    with _TRANSCRIPTS_LOCK:
        transcript = list(_TRANSCRIPTS.get(sid or "", [])) if sid else []
    log.debug("GET /api/live -> in_progress=%s, sid=%s, entries=%s", bool(sid), _mask_sid(sid), len(transcript))
    return jsonify({
        "ok": True,
        "in_progress": bool(sid),
        "callSid": sid or "",
        "transcript": transcript,
        "media_streams_enabled": bool(_runtime.enable_media_streams),
    })


# History APIs
@app.route("/api/history", methods=["GET"])
def api_history_list():
    items = _scan_history_summaries()
    log.info("GET /api/history -> %s items", len(items))
    return jsonify({"calls": items})


@app.route("/api/history/<sid>", methods=["GET"])
def api_history_detail(sid: str):
    d = _load_call_history(sid)
    if not d:
        log.info("GET /api/history/%s -> 404", _mask_sid(sid))
        return Response("Not found", status=404)
    log.info("GET /api/history/%s -> ok", _mask_sid(sid))
    return jsonify(d)


@app.route("/api/recording/<recording_sid>", methods=["GET"])
def api_recording_proxy(recording_sid: str):
    account_sid = os.environ.get("TWILIO_ACCOUNT_SID", "")
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN", "")
    if not account_sid or not auth_token:
        log.error("Recording fetch failed: Twilio credentials not configured.")
        return Response("Twilio credentials not configured.", status=500)
    url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Recordings/{recording_sid}.mp3"
    req = urllib.request.Request(url)
    b64 = base64.b64encode(f"{account_sid}:{auth_token}".encode("utf-8")).decode("ascii")
    req.add_header("Authorization", f"Basic {b64}")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read()
            log.info("Proxied recording %s (%s bytes).", recording_sid, len(data))
            return Response(data, status=200, mimetype="audio/mpeg")
    except Exception as e:
        log.error("Failed to stream recording %s: %s", recording_sid, e)
        return Response("Recording unavailable.", status=404)


# One-shot greeting setter
_ONE_SHOT_GREETING: Optional[str] = None
_ONE_SHOT_GREETING_LOCK = threading.Lock()


def _pop_one_shot_opening() -> Optional[str]:
    global _ONE_SHOT_GREETING
    with _ONE_SHOT_GREETING_LOCK:
        val = _ONE_SHOT_GREETING
        _ONE_SHOT_GREETING = None
        if val:
            log.info("One-shot greeting consumed (len=%s).", len(val))
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
        log.info("POST /api/next-greeting rejected: words=%s", len(words))
        return Response("Phrase must be between 5 and 15 words.", status=400)
    global _ONE_SHOT_GREETING
    with _ONE_SHOT_GREETING_LOCK:
        _ONE_SHOT_GREETING = phrase
    log.info("POST /api/next-greeting accepted: words=%s, len=%s", len(words), len(phrase))
    return jsonify(ok=True)


@app.route("/api/diag/state", methods=["GET"])
def api_diag_state():
    # Expose a concise snapshot for troubleshooting
    now_ts = int(time.time())
    pend = _is_outgoing_pending()
    active_sid = _get_current_call_sid()
    ready, reasons = _diagnostics_ready_to_call()
    can_now, wait_s = (True, 0)
    if _runtime.to_number:
        can_now, wait_s = _can_attempt(now_ts, _runtime.to_number)
    with _next_call_epoch_s_lock:
        next_epoch = _next_call_epoch_s
        interval_total = _interval_total_seconds
        interval_start = _interval_start_epoch_s
    payload = {
        "active_sid": active_sid,
        "pending": pend,
        "ready": ready,
        "reasons": reasons,
        "can_attempt": can_now,
        "wait_if_capped": wait_s,
        "to": _runtime.to_number,
        "from": _runtime.from_number,
        "from_pool": _runtime.from_numbers,
        "public_base_url": _runtime.public_base_url,
        "active_hours_local": _runtime.active_hours_local,
        "active_days": _runtime.active_days,
        "next_call_epoch": next_epoch,
        "interval_total": interval_total,
        "interval_start": interval_start,
    }
    log.info("GET /api/diag/state -> %s", {**payload, "to": _mask_phone(payload["to"]), "from": _mask_phone(payload["from"])})
    return jsonify(payload)


def _build_opening_lines_for_sid(call_sid: str) -> List[str]:
    one = _pop_one_shot_opening()
    if one:
        lines = [one]
    else:
        params = _get_params_for_sid(call_sid)
        base_dialog = _get_dialog_lines(params.dialog_idx)
        first = base_dialog[0] if base_dialog else "Hello."
        lines = [first]
    if _runtime.company_name:
        lines.append(f"This is {_runtime.company_name}.")
    if _runtime.topic:
        lines.append(f"I am calling about {_runtime.topic}.")
    log.info("Opening lines prepared for %s: count=%s", _mask_sid(call_sid), len(lines))
    return [ln for ln in lines if ln]


# Twilio voice routes
@app.route("/voice", methods=["POST", "GET"])
def voice_entrypoint():
    if VoiceResponse is None:
        log.error("Server missing Twilio TwiML library.")
        return Response("Server missing Twilio TwiML library.", status=500)
    vr = VoiceResponse()

    call_sid = request.values.get("CallSid", "") or None
    log.info(
        "ENTRY /voice: CallSid=%s, To=%s, From=%s, Method=%s",
        _mask_sid(call_sid),
        _mask_phone(request.values.get("To") or _runtime.to_number),
        _mask_phone(request.values.get("From")),
        request.method,
    )
    if call_sid:
        _set_current_call_sid(call_sid)
        _clear_outgoing_pending()
        _assign_params_to_sid(call_sid)
        _init_call_meta_if_absent(
            call_sid,
            to=(request.values.get("To") or _runtime.to_number or ""),
            from_n=(request.values.get("From") or ""),
            started_at=int(time.time()),
        )

    # Optional Media Streams
    if _runtime.enable_media_streams and Start is not None and Stream is not None and _runtime.public_base_url:
        try:
            start = Start()
            ws_base = _runtime.public_base_url.replace("http:", "ws:").replace("https:", "wss:")
            start.stream(url=f"{ws_base}/media-in", track="inbound_track")
            start.stream(url=f"{ws_base}/media-out", track="outbound_track")
            vr.append(start)
            log.info("Attached media streams to call.")
        except Exception as e:
            log.warning("Failed to attach media streams: %s", e)

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
    vr.append(g)
    vr.redirect(url_for("hello_got_speech", _external=True), method="POST")
    return Response(str(vr), status=200, mimetype="text/xml")


@app.route("/hello", methods=["POST"])
def hello_got_speech():
    if VoiceResponse is None:
        log.error("Server missing Twilio TwiML library.")
        return Response("Server missing Twilio TwiML library.", status=500)
    vr = VoiceResponse()

    call_sid = request.values.get("CallSid", "") or ""
    log.info("ENTRY /hello: CallSid=%s", _mask_sid(call_sid))
    if call_sid:
        _set_current_call_sid(call_sid)
        _clear_outgoing_pending()
        _assign_params_to_sid(call_sid)
        _init_call_meta_if_absent(
            call_sid,
            to=(request.values.get("To") or _runtime.to_number or ""),
            from_n=(request.values.get("From") or ""),
            started_at=int(time.time()),
        )

    speech_text = (request.values.get("SpeechResult") or "").strip()
    log.info("Hello stage SpeechResult present=%s, len=%s", bool(speech_text), len(speech_text))
    if speech_text:
        _append_transcript(call_sid, "Callee", speech_text, is_final=True)

    params = _get_params_for_sid(call_sid)
    opening_lines = _build_opening_lines_for_sid(call_sid)
    for i, line in enumerate(opening_lines):
        _append_transcript(call_sid, "Assistant", line, is_final=True)
        vr.say(line, voice=params.voice, language=_runtime.tts_language)
        if i < len(opening_lines) - 1:
            vr.pause(length=1)

    g = Gather(
        input="speech",
        method="POST",
        action=url_for("dialog", turn=1, _external=True),
        timeout=str(_runtime.callee_silence_hangup_seconds),
        speech_timeout="auto",
        barge_in=True,
        partial_result_callback=url_for("transcribe_partial", stage="dialog", seq=1, _external=True),
        partial_result_callback_method="POST",
        language=_runtime.tts_language,
    )
    vr.append(g)
    vr.say("Goodbye.", voice=params.voice, language=_runtime.tts_language)
    vr.hangup()
    return Response(str(vr), status=200, mimetype="text/xml")


@app.route("/dialog", methods=["POST"])
def dialog():
    if VoiceResponse is None:
        log.error("Server missing Twilio TwiML library.")
        return Response("Server missing Twilio TwiML library.", status=500)
    vr = VoiceResponse()

    call_sid = request.values.get("CallSid", "") or ""
    turn = _parse_int(request.args.get("turn"), 1)
    log.info("ENTRY /dialog: CallSid=%s, turn=%s", _mask_sid(call_sid), turn)

    _set_current_call_sid(call_sid or _get_current_call_sid())

    speech_text = (request.values.get("SpeechResult") or "").strip()
    log.info("Dialog SpeechResult present=%s, len=%s", bool(speech_text), len(speech_text))
    if speech_text:
        _append_transcript(call_sid, "Callee", speech_text, is_final=True)

    params = _get_params_for_sid(call_sid)
    reply_lines = _compose_assistant_reply(call_sid, turn)
    log.info("Assistant reply line count=%s", len(reply_lines))
    for i, line in enumerate(reply_lines):
        _append_transcript(call_sid, "Assistant", line, is_final=True)
        vr.say(line, voice=params.voice, language=_runtime.tts_language)
        if i < len(reply_lines) - 1:
            vr.pause(length=1)

    if turn < _runtime.max_dialog_turns:
        next_turn = turn + 1
        g = Gather(
            input="speech",
            method="POST",
            action=url_for("dialog", turn=next_turn, _external=True),
            timeout=str(_runtime.callee_silence_hangup_seconds),
            speech_timeout="auto",
            barge_in=True,
            partial_result_callback=url_for("transcribe_partial", stage="dialog", seq=next_turn, _external=True),
            partial_result_callback_method="POST",
            language=_runtime.tts_language,
        )
        vr.append(g)
        vr.say("Goodbye.", voice=params.voice, language=_runtime.tts_language)
        vr.hangup()
    else:
        vr.say("Goodbye.", voice=params.voice, language=_runtime.tts_language)
        vr.hangup()

    return Response(str(vr), status=200, mimetype="text/xml")


@app.route("/transcribe-partial", methods=["POST"])
def transcribe_partial():
    call_sid = request.values.get("CallSid", "") or ""
    stage = request.args.get("stage") or "unknown"
    seq = request.args.get("seq") or ""
    _set_current_call_sid(call_sid or _get_current_call_sid())
    part = (request.values.get("UnstableSpeechResult") or request.values.get("SpeechResult") or "").strip()
    log.debug("Partial transcription: stage=%s seq=%s sid=%s present=%s len=%s", stage, seq, _mask_sid(call_sid), bool(part), len(part))
    if part:
        _append_transcript(call_sid, "Callee", part, is_final=False)
    return ("", 204)


@app.route("/status", methods=["POST"])
def status_callback():
    call_sid = request.values.get("CallSid", "") or ""
    call_status = (request.values.get("CallStatus") or "").lower()
    answered_by = request.values.get("AnsweredBy") or ""
    sip_code = request.values.get("SipResponseCode") or ""
    duration = request.values.get("CallDuration") or ""
    to_n = request.values.get("To") or ""
    from_n = request.values.get("From") or ""

    log.info(
        "Twilio status: sid=%s status=%s answered_by=%s sip=%s duration=%s to=%s from=%s",
        _mask_sid(call_sid),
        call_status,
        answered_by,
        sip_code,
        duration,
        _mask_phone(to_n),
        _mask_phone(from_n),
    )

    now = int(time.time())

    if call_status in ("initiated", "ringing", "in-progress", "answered"):
        if call_sid:
            _set_current_call_sid(call_sid)
            _init_call_meta_if_absent(call_sid, to=to_n, from_n=from_n, started_at=now)
        _clear_outgoing_pending()

    if call_status == "completed":
        _set_current_call_sid(None)
        _clear_outgoing_pending()
        dur_i = _parse_int(duration, 0)
        with _CALL_META_LOCK:
            meta = _CALL_META.setdefault(call_sid, {})
            meta["completed_at"] = now
            meta["duration_seconds"] = dur_i
            cp = _CALL_PARAMS_BY_SID.get(call_sid)
            if cp:
                meta["voice"] = cp.voice
                meta["dialog_idx"] = cp.dialog_idx
        _persist_call_history(call_sid)
        with _TRANSCRIPTS_LOCK:
            _TRANSCRIPTS.pop(call_sid, None)
        _reset_schedule_after_completion(now)

    return ("", 204)


@app.route("/recording-status", methods=["POST"])
def recording_status():
    call_sid = request.values.get("CallSid", "") or ""
    rec_sid = request.values.get("RecordingSid", "") or ""
    status = (request.values.get("RecordingStatus") or "").lower()
    log.info("Recording status: call=%s rec=%s status=%s", _mask_sid(call_sid), rec_sid, status)
    if call_sid and rec_sid:
        with _CALL_META_LOCK:
            meta = _CALL_META.setdefault(call_sid, {})
            recs = meta.setdefault("recordings", [])
            if status in ("in-progress", "completed"):
                if not any(r.get("recording_sid") == rec_sid for r in recs):
                    recs.append({"recording_sid": rec_sid, "status": status})
            else:
                for r in recs:
                    if r.get("recording_sid") == rec_sid:
                        r["status"] = status
                        break
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
    drop_count = 0
    for ws in clients:
        try:
            ws.send(payload_b64)
        except Exception:
            drop_count += 1
            try:
                with _AUDIO_CLIENTS_LOCK:
                    _AUDIO_CLIENTS.discard(ws)
            except Exception:
                pass
    if drop_count:
        log.info("Cleaned up %s disconnected audio clients.", drop_count)


if _sock is not None:
    @_sock.route("/media-in")
    def media_in(ws):  # type: ignore
        log.info("WebSocket connected: /media-in")
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
        except Exception as e:
            log.warning("WebSocket /media-in closed with error: %s", e)
        finally:
            log.info("WebSocket disconnected: /media-in")

    @_sock.route("/media-out")
    def media_out(ws):  # type: ignore
        log.info("WebSocket connected: /media-out")
        try:
            while True:
                msg = ws.receive()
                if msg is None:
                    break
        except Exception as e:
            log.warning("WebSocket /media-out closed with error: %s", e)
        finally:
            log.info("WebSocket disconnected: /media-out")

    @_sock.route("/client-audio")
    def client_audio(ws):  # type: ignore
        with _AUDIO_CLIENTS_LOCK:
            _AUDIO_CLIENTS.add(ws)
        log.info("WebSocket client connected: /client-audio (clients=%s)", len(_AUDIO_CLIENTS))
        try:
            while True:
                msg = ws.receive()
                if msg is None:
                    break
        except Exception as e:
            log.warning("WebSocket /client-audio closed with error: %s", e)
        finally:
            with _AUDIO_CLIENTS_LOCK:
                _AUDIO_CLIENTS.discard(ws)
            log.info("WebSocket client disconnected: /client-audio (clients=%s)", len(_AUDIO_CLIENTS))


# Ngrok management
_active_tunnel_url: Optional[str] = None


def _start_ngrok_if_enabled() -> None:
    global _active_tunnel_url
    if not _runtime.use_ngrok:
        log.info("Ngrok disabled (USE_NGROK=false).")
        return
    if ngrok_lib is None:
        log.warning("USE_NGROK=true but pyngrok is not installed. Skipping.")
        return
    try:
        if _active_tunnel_url:
            log.info("Ngrok already active at %s", _active_tunnel_url)
            return
        port = _runtime.flask_port or 8080
        tun = ngrok_lib.connect(addr=port, proto="http")
        _active_tunnel_url = tun.public_url  # type: ignore
        os.environ["PUBLIC_BASE_URL"] = _active_tunnel_url
        _runtime.public_base_url = _active_tunnel_url
        log.info("ngrok tunnel active at %s", _active_tunnel_url)
    except Exception as e:
        log.error("Failed to start ngrok: %s", e)


@atexit.register
def _shutdown_ngrok():
    try:
        if ngrok_lib is not None:
            ngrok_lib.kill()
            log.info("ngrok terminated at exit.")
    except Exception:
        pass


def _handle_termination(signum, frame):
    log.info("Termination signal received (%s). Stopping service.", signum)
    try:
        _stop_requested.set()
    except Exception:
        pass
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
        log.info("Background dialer thread started.")


@app.route("/api/call-now", methods=["POST"])
def api_call_now():
    log.info("POST /api/call-now received.")
    ready, reasons = _diagnostics_ready_to_call()
    if not ready:
        log.error("Call-now rejected; not ready: %s", reasons)
        return jsonify(ok=False, reason="not_ready", message="Service not ready for outbound calls.", reasons=reasons), 400

    # Optional direct dial path to eliminate timing/race issues during diagnostics
    direct = _parse_bool(os.environ.get("DIRECT_DIAL_ON_TRIGGER"), True)

    if not _within_active_window(_now_local()):
        msg = "Outside active calling window."
        log.info("Call-now inside=%s -> %s", False, msg)
        return jsonify(ok=False, reason="outside_active_window", message=msg), 200
    if not _runtime.to_number:
        log.info("Call-now missing destination TO_NUMBER.")
        return jsonify(ok=False, reason="missing_destination", message="TO_NUMBER is not configured."), 400

    if _get_current_call_sid() is not None:
        log.info("Call-now suppressed; call already in progress.")
        return jsonify(ok=False, reason="already_in_progress", message="A call is already in progress."), 409
    if _is_outgoing_pending():
        log.info("Call-now suppressed; outgoing pending in effect.")
        return jsonify(ok=False, reason="pending", message="A call request is already pending."), 409

    now = int(time.time())
    allowed, wait_s = _can_attempt(now, _runtime.to_number)
    if not allowed:
        log.info("Call-now capped; wait %s seconds.", wait_s)
        return jsonify(ok=False, reason="cap_reached", wait_seconds=wait_s), 429

    if direct:
        log.info("Call-now taking direct path (DIRECT_DIAL_ON_TRIGGER=true).")
        gates = _log_dialer_gates("direct_call_now")
        ok = _place_call_now()
        log.info("Direct call-now place_call_now result=%s", ok)
        if ok:
            return jsonify(ok=True, started=True)
        return jsonify(ok=False, reason="twilio_error", message="Twilio call placement failed; see server logs."), 502

    # Fallback to dialer-thread path
    _mark_outgoing_pending()
    _manual_call_requested.set()
    log.info("Call-now accepted; manual request queued.")
    return jsonify(ok=True, queued=True)


@app.route("/health", methods=["GET"])
def health():
    return jsonify(ok=True, ts=int(time.time()))


def main():
    log.info("Scam Call Console starting.")
    # Log masked account SID if present
    acc = os.environ.get("TWILIO_ACCOUNT_SID", "")
    if acc:
        log.info("Twilio Account SID present (masked): %s", _mask_sid(acc))
    _log_runtime_summary(context="startup")
    _start_ngrok_if_enabled()
    _start_background_threads()
    host = _runtime.flask_host or os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(_runtime.flask_port or _parse_int(os.environ.get("FLASK_PORT"), 8080))
    debug = bool(_runtime.flask_debug or _parse_bool(os.environ.get("FLASK_DEBUG"), False))
    log.info("Starting Flask on %s:%s (debug=%s)", host, port, debug)
    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    main()
