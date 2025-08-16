#!/usr/bin/env python3
from __future__ import annotations

import atexit
import base64
import csv
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

try:
    from twilio.http.http_client import TwilioHttpClient  # type: ignore
except Exception:
    TwilioHttpClient = None  # type: ignore

try:
    from pyngrok import ngrok as ngrok_lib  # type: ignore
except Exception:
    ngrok_lib = None  # type: ignore

try:
    from flask_sock import Sock  # type: ignore
except Exception:
    Sock = None  # type: ignore

# Optional rotating prompts
try:
    from rotating_iv_prompts import PROMPTS as IV_PROMPTS  # type: ignore
except Exception:
    IV_PROMPTS = []  # type: ignore


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


def _xml_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")


app = Flask(__name__, static_folder="static", template_folder="templates")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)  # type: ignore
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(32))

TRUE_SET = {"1", "true", "yes", "on", "y", "t"}

DATA_DIR = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
HISTORY_CSV_PATH = DATA_DIR / "call_history.csv"
HISTORY_DIR = Path("data/history")
HISTORY_DIR.mkdir(parents=True, exist_ok=True)
SMS_HISTORY_DIR = Path("data/sms_history")
SMS_HISTORY_DIR.mkdir(parents=True, exist_ok=True)

# Messages list (for rotation)
MESSAGES_FILE = DATA_DIR / "messages.json"
_USER_MESSAGES_LOCK = threading.Lock()
_USER_MESSAGES: List[str] = []


def _parse_bool(s: Optional[str], default: bool = False) -> bool:
    if s is None:
        return default
    return str(s).strip().lower() in TRUE_SET


def _parse_int(s: Optional[str], default: int) -> int:
    try:
        return int(str(s).strip())
    except Exception:
        return default


def _parse_float(s: Optional[str], default: float) -> float:
    try:
        return float(str(s).strip())
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
    tts_rate_percent: int = 100
    tts_pitch_semitones: int = 0
    tts_volume_db: int = 0

    greeting_pause_seconds: float = 1.0
    response_pause_seconds: float = 0.5
    between_phrases_pause_seconds: float = 1.0

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

    twilio_http_timeout_seconds: int = 10


@dataclass
class SMSConfig:
    enabled: bool = False
    to_number: str = ""
    from_number: str = ""
    from_numbers: List[str] = field(default_factory=list)

    active_hours_local: str = ""
    active_days: List[str] = field(default_factory=list)

    min_interval_seconds: int = 300
    max_interval_seconds: int = 900
    hourly_max_attempts: int = 3
    daily_max_attempts: int = 20

    template: str = ""
    rotate_prompts: bool = True
    rotate_prompts_strategy: str = "random"


_runtime = RuntimeConfig()
_sms_runtime = SMSConfig()

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
    "TTS_RATE_PERCENT",
    "TTS_PITCH_SEMITONES",
    "TTS_VOLUME_DB",
    "GREETING_PAUSE_SECONDS",
    "RESPONSE_PAUSE_SECONDS",
    "BETWEEN_PHRASES_PAUSE_SECONDS",
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
    "TWILIO_HTTP_TIMEOUT_SECONDS",
    # SMS
    "SMS_ENABLED",
    "SMS_TO_NUMBER",
    "SMS_FROM_NUMBER",
    "SMS_FROM_NUMBERS",
    "SMS_ACTIVE_HOURS_LOCAL",
    "SMS_ACTIVE_DAYS",
    "SMS_MIN_INTERVAL_SECONDS",
    "SMS_MAX_INTERVAL_SECONDS",
    "SMS_HOURLY_MAX_ATTEMPTS_PER_DEST",
    "SMS_DAILY_MAX_ATTEMPTS_PER_DEST",
    "SMS_TEMPLATE",
    "SMS_ROTATE_PROMPTS",
    "SMS_ROTATE_PROMPTS_STRATEGY",
]
_SECRET_ENV_KEYS = {
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "ADMIN_PASSWORD_HASH",
    "ADMIN_USER",
    "FLASK_SECRET",
}


def _normalize_day_name(s: str) -> Optional[str]:
    if not s:
        return None
    t = s.strip().lower()
    mapping = {
        "mon": "Mon", "monday": "Mon",
        "tue": "Tue", "tues": "Tue", "tuesday": "Tue",
        "wed": "Wed", "weds": "Wed", "wednesday": "Wed",
        "thu": "Thu", "thur": "Thu", "thurs": "Thu", "thursday": "Thu",
        "fri": "Fri", "friday": "Fri",
        "sat": "Sat", "saturday": "Sat",
        "sun": "Sun", "sunday": "Sun",
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
    _runtime.tts_rate_percent = max(50, min(200, _parse_int(os.environ.get("TTS_RATE_PERCENT"), 100)))
    _runtime.tts_pitch_semitones = max(-12, min(12, _parse_int(os.environ.get("TTS_PITCH_SEMITONES"), 0)))
    _runtime.tts_volume_db = max(-6, min(6, _parse_int(os.environ.get("TTS_VOLUME_DB"), 0)))

    def clamp_float(val, lo, hi, default):
        try:
            v = float(val)
        except Exception:
            v = default
        v = max(lo, min(hi, v))
        return round(v, 2)

    _runtime.greeting_pause_seconds = clamp_float(os.environ.get("GREETING_PAUSE_SECONDS"), 0.0, 5.0, 1.0)
    _runtime.response_pause_seconds = clamp_float(os.environ.get("RESPONSE_PAUSE_SECONDS"), 0.0, 5.0, 0.5)
    _runtime.between_phrases_pause_seconds = clamp_float(os.environ.get("BETWEEN_PHRASES_PAUSE_SECONDS") or os.environ.get("BETWEEN_PHRASES_PAUSES_SECONDS"), 0.0, 5.0, 1.0)

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

    _runtime.twilio_http_timeout_seconds = max(3, _parse_int(os.environ.get("TWILIO_HTTP_TIMEOUT_SECONDS"), 10))


def _load_sms_runtime_from_env() -> None:
    _sms_runtime.enabled = _parse_bool(os.environ.get("SMS_ENABLED"), False)
    _sms_runtime.to_number = (os.environ.get("SMS_TO_NUMBER") or "").strip()
    _sms_runtime.from_number = (os.environ.get("SMS_FROM_NUMBER") or "").strip()
    _sms_runtime.from_numbers = _parse_csv(os.environ.get("SMS_FROM_NUMBERS"))

    _sms_runtime.active_hours_local = (os.environ.get("SMS_ACTIVE_HOURS_LOCAL") or "").strip()
    days = _parse_csv(os.environ.get("SMS_ACTIVE_DAYS") or "")
    _sms_runtime.active_days = [d for d in ([_normalize_day_name(x) for x in days]) if d]

    _sms_runtime.min_interval_seconds = max(60, _parse_int(os.environ.get("SMS_MIN_INTERVAL_SECONDS"), 300))
    _sms_runtime.max_interval_seconds = max(_sms_runtime.min_interval_seconds, _parse_int(os.environ.get("SMS_MAX_INTERVAL_SECONDS"), 900))
    _sms_runtime.hourly_max_attempts = max(1, _parse_int(os.environ.get("SMS_HOURLY_MAX_ATTEMPTS_PER_DEST"), 3))
    _sms_runtime.daily_max_attempts = max(_sms_runtime.hourly_max_attempts, _parse_int(os.environ.get("SMS_DAILY_MAX_ATTEMPTS_PER_DEST"), 20))

    _sms_runtime.template = (os.environ.get("SMS_TEMPLATE") or "").strip()
    _sms_runtime.rotate_prompts = _parse_bool(os.environ.get("SMS_ROTATE_PROMPTS"), True)
    _sms_runtime.rotate_prompts_strategy = (os.environ.get("SMS_ROTATE_PROMPTS_STRATEGY") or "random").strip().lower()


_load_runtime_from_env()
_load_sms_runtime_from_env()


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
    for k, v in updates.items():
        if k in _EDITABLE_ENV_KEYS and k not in _SECRET_ENV_KEYS:
            os.environ[k] = "" if v is None else str(v)
    _write_env_updates_preserving_comments(updates)
    _load_runtime_from_env()
    _load_sms_runtime_from_env()
    _log_runtime_summary(context="after env update")


_attempts_lock = threading.Lock()
_dest_attempts: Dict[str, List[float]] = {}
_next_call_epoch_s_lock = threading.Lock()
_next_call_epoch_s: Optional[int] = None
_interval_start_epoch_s: Optional[int] = None
_interval_total_seconds: Optional[int] = None

_CURRENT_CALL_LOCK = threading.Lock()
_CURRENT_CALL_SID: Optional[str] = None

_PENDING_LOCK = threading.Lock()
_PENDING_UNTIL_TS: Optional[float] = None
_PENDING_TTL_SECONDS = 30.0

_LAST_DIAL_ERROR_LOCK = threading.Lock()
_LAST_DIAL_ERROR: Optional[Dict[str, Any]] = None


def _set_last_dial_error(message: str) -> None:
    global _LAST_DIAL_ERROR
    with _LAST_DIAL_ERROR_LOCK:
        _LAST_DIAL_ERROR = {"ts": int(time.time()), "message": message or "unknown error"}


def _clear_last_dial_error() -> None:
    global _LAST_DIAL_ERROR
    with _LAST_DIAL_ERROR_LOCK:
        _LAST_DIAL_ERROR = None


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


@dataclass
class CallParams:
    voice: str
    dialog_idx: int


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


def _select_next_call_params_locked() -> CallParams:
    global _PLACED_CALL_COUNT, _LAST_DIALOG_IDX
    _PLACED_CALL_COUNT += 1
    voice = "man" if (_PLACED_CALL_COUNT % 2 == 1) else "woman"
    _LAST_DIALOG_IDX = (_LAST_DIALOG_IDX + 1) % max(1, len(_DIALOGS))
    return CallParams(voice=voice, dialog_idx=_LAST_DIALOG_IDX)


def _prepare_params_for_next_call() -> None:
    global _PENDING_CALL_PARAMS
    acquired = _PARAMS_LOCK.acquire(timeout=10.0)
    if not acquired:
        raise RuntimeError("Lock acquisition timeout")
    try:
        _PENDING_CALL_PARAMS = _select_next_call_params_locked()
    finally:
        _PARAMS_LOCK.release()


def _assign_params_to_sid(sid: str) -> None:
    global _PENDING_CALL_PARAMS
    if not sid:
        return
    acquired = _PARAMS_LOCK.acquire(timeout=10.0)
    if not acquired:
        return
    try:
        if _PENDING_CALL_PARAMS is None:
            _PENDING_CALL_PARAMS = _select_next_call_params_locked()
        _CALL_PARAMS_BY_SID[sid] = _PENDING_CALL_PARAMS
        _PENDING_CALL_PARAMS = None
    finally:
        _PARAMS_LOCK.release()


def _get_params_for_sid(sid: str) -> CallParams:
    acquired = _PARAMS_LOCK.acquire(timeout=10.0)
    if not acquired:
        return CallParams(voice=_runtime.tts_voice or "man", dialog_idx=0)
    try:
        cp = _CALL_PARAMS_BY_SID.get(sid)
        if cp:
            return cp
        return CallParams(voice=_runtime.tts_voice or "man", dialog_idx=0)
    finally:
        _PARAMS_LOCK.release()


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
        priv_prefix = tuple([f"172.{i}." for i in range(16, 32)]) + ("10.", "192.168.")
        if host.startswith(priv_prefix):
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
    fatal = [r for r in reasons if r in ("missing_to_number", "missing_from_number", "twilio_client_not_initialized")]
    return (len(fatal) == 0), reasons


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
            wait = max(1, (int(oldest) + 3600) - now_ts)
            return False, wait
        if len(lst) >= _runtime.daily_max_attempts:
            return False, 3600
    return True, 0


def _compute_next_interval_seconds() -> int:
    lo = max(30, int(_runtime.min_interval_seconds))
    hi = max(lo, int(_runtime.max_interval_seconds))
    if lo == hi:
        return lo
    return random.randint(lo, hi)


_twilio_client: Optional[Client] = None


def _ensure_twilio_client() -> Optional[Client]:
    global _twilio_client
    if _twilio_client is not None:
        return _twilio_client
    if Client is None:
        log.error("Twilio SDK not available.")
        return None
    sid = os.environ.get("TWILIO_ACCOUNT_SID")
    tok = os.environ.get("TWILIO_AUTH_TOKEN")
    if not sid or not tok:
        log.error("Missing TWILIO_ACCOUNT_SID or TWILIO_AUTH_TOKEN.")
        return None
    http_client = None
    if TwilioHttpClient is not None:
        try:
            http_client = TwilioHttpClient(timeout=_runtime.twilio_http_timeout_seconds)
        except Exception:
            http_client = None
    _twilio_client = Client(sid, tok, http_client=http_client) if http_client else Client(sid, tok)
    return _twilio_client


def _choose_from_number() -> Optional[str]:
    if _runtime.from_numbers:
        return random.choice(_runtime.from_numbers)
    return _runtime.from_number or None


_manual_call_requested = threading.Event()
_stop_requested = threading.Event()
_dialer_thread: Optional[threading.Thread] = None


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


def _place_call_now() -> bool:
    client = _ensure_twilio_client()
    from_n = _choose_from_number()
    to_n = _runtime.to_number
    public_url = _runtime.public_base_url or ""
    if not client or not to_n or not from_n or not public_url:
        _set_last_dial_error("Missing Twilio client, numbers, or PUBLIC_BASE_URL")
        return False
    try:
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
        call = client.calls.create(**kwargs)  # type: ignore
        sid = getattr(call, "sid", "") or ""
        _clear_last_dial_error()
        _note_attempt(time.time(), to_n)
        _mark_outgoing_pending()
        if sid:
            _assign_params_to_sid(sid)
            _init_call_meta_if_absent(sid, to=to_n, from_n=from_n, started_at=int(time.time()))
        return True
    except Exception as e:
        _set_last_dial_error(f"Twilio call placement failed: {e}")
        return False


def _log_runtime_summary(context: str = "startup") -> None:
    ready, reasons = _diagnostics_ready_to_call()
    log.info(
        "Runtime summary (%s): to=%s, from_single=%s, pool=%s, active=%s %s, interval=%s..%s, caps=%s/%s, media=%s, ngrok=%s, ready=%s, reasons=%s; SMS(enabled=%s, to=%s, pool=%s)",
        context,
        _mask_phone(_runtime.to_number),
        _mask_phone(_runtime.from_number),
        ",".join(_runtime.from_numbers) or "-",
        _runtime.active_hours_local,
        ",".join(_runtime.active_days),
        _runtime.min_interval_seconds,
        _runtime.max_interval_seconds,
        _runtime.hourly_max_attempts,
        _runtime.daily_max_attempts,
        _runtime.enable_media_streams,
        _runtime.use_ngrok,
        ready,
        reasons,
        _sms_runtime.enabled,
        _mask_phone(_sms_runtime.to_number),
        ",".join(_sms_runtime.from_numbers) or (_sms_runtime.from_number or "-"),
    )


def _dialer_loop() -> None:
    while not _stop_requested.is_set():
        try:
            now = int(time.time())
            _initialize_schedule_if_needed(now)

            if _manual_call_requested.is_set():
                _manual_call_requested.clear()
                ready, reasons = _diagnostics_ready_to_call()
                if ready and not _get_current_call_sid() and _within_active_window(_now_local()):
                    can, _wait = _can_attempt(now, _runtime.to_number) if _runtime.to_number else (True, 0)
                    if can:
                        ok = _place_call_now()
                        if not ok:
                            _reset_schedule_after_completion(now)
                else:
                    _reset_schedule_after_completion(now)

            with _next_call_epoch_s_lock:
                ready_time = (_next_call_epoch_s is not None and now >= _next_call_epoch_s)

            if ready_time:
                ready, reasons = _diagnostics_ready_to_call()
                if ready and not _is_outgoing_pending() and not _get_current_call_sid() and _within_active_window(_now_local()):
                    can, _wait = _can_attempt(now, _runtime.to_number) if _runtime.to_number else (True, 0)
                    if can:
                        ok = _place_call_now()
                        if not ok:
                            _reset_schedule_after_completion(now)
                    else:
                        _reset_schedule_after_completion(now)
                else:
                    _reset_schedule_after_completion(now)

            time.sleep(0.2)
        except Exception:
            time.sleep(0.5)


_TRANSCRIPTS_LOCK = threading.Lock()
_TRANSCRIPTS: Dict[str, List[Dict[str, Any]]] = {}

_CALL_META_LOCK = threading.Lock()
_CALL_META: Dict[str, Dict[str, Any]] = {}


def _append_transcript(call_sid: str, role: str, text: str, is_final: bool) -> None:
    if not text:
        return
    entry = {"t": time.time(), "role": role, "text": text, "final": bool(is_final)}
    with _TRANSCRIPTS_LOCK:
        _TRANSCRIPTS.setdefault(call_sid, []).append(entry)


def _init_call_meta_if_absent(sid: str, **kwargs: Any) -> None:
    with _CALL_META_LOCK:
        meta = _CALL_META.get(sid)
        if meta is None:
            meta = {}
            _CALL_META[sid] = meta
        for k, v in kwargs.items():
            if k not in meta or meta.get(k) in (None, "", 0):
                meta[k] = v


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
    items: List[Tuple[float, Dict[str, Any]]] = []
    seen_sids: Set[str] = set()
    try:
        for f in HISTORY_DIR.glob("*.json"):
            try:
                d = json.loads(f.read_text(encoding="utf-8"))
                meta = d.get("meta", {}) or {}
                sid = d.get("sid", "") or ""
                started = meta.get("started_at")
                try:
                    started_val = int(started) if started is not None else None
                except Exception:
                    started_val = None
                out = {
                    "sid": sid,
                    "started_at": started_val,
                    "completed_at": meta.get("completed_at"),
                    "to": meta.get("to"),
                    "from": meta.get("from"),
                    "duration_seconds": meta.get("duration_seconds"),
                    "has_recordings": bool(meta.get("recordings")),
                }
                mtime = f.stat().st_mtime
                items.append((mtime, out))
                if sid:
                    seen_sids.add(sid)
            except Exception:
                continue
    except Exception:
        return []

    try:
        if HISTORY_CSV_PATH.exists():
            try:
                with HISTORY_CSV_PATH.open("r", encoding="utf-8", newline="") as csvf:
                    reader = csv.DictReader(csvf)
                    for r in reader:
                        sid = (r.get("callSid") or r.get("callSid".lower()) or "").strip()
                        if not sid:
                            continue
                        if sid in seen_sids:
                            continue
                        started_raw = r.get("startedAt") or r.get("started_at") or ""
                        started_at = None
                        if started_raw:
                            started_raw = started_raw.strip()
                            try:
                                dt = datetime.fromisoformat(started_raw)
                                started_at = int(dt.timestamp())
                            except Exception:
                                try:
                                    started_at = int(float(started_raw))
                                except Exception:
                                    started_at = None
                        dur = 0
                        try:
                            dur = int(float(r.get("durationSec") or r.get("duration_sec") or r.get("duration") or 0))
                        except Exception:
                            dur = 0
                        out = {
                            "sid": sid,
                            "started_at": started_at,
                            "completed_at": None,
                            "to": r.get("to") or "",
                            "from": r.get("from") or "",
                            "duration_seconds": dur,
                            "has_recordings": False,
                        }
                        try:
                            mtime = HISTORY_CSV_PATH.stat().st_mtime
                        except Exception:
                            mtime = time.time()
                        items.append((mtime, out))
                        seen_sids.add(sid)
            except Exception as e:
                log.warning("Failed to read legacy history CSV %s: %s", HISTORY_CSV_PATH, e)
    except Exception:
        pass

    items.sort(key=lambda t: t[0], reverse=True)
    out: List[Dict[str, Any]] = []
    for _, obj in items[:limit]:
        out.append(obj)
    return out


def _compute_history_metrics() -> Dict[str, Any]:
    summaries = _scan_history_summaries(limit=1000000)
    total_calls = len(summaries)
    total_duration = 0
    for s in summaries:
        try:
            ds = int(s.get("duration_seconds") or 0)
        except Exception:
            ds = 0
        total_duration += ds
    avg = int(total_duration / total_calls) if total_calls else 0
    return {"total_calls": total_calls, "total_duration_seconds": total_duration, "average_call_seconds": avg}


def _public_url_ok() -> bool:
    return bool(_runtime.public_base_url)


# UI routes
@app.route("/")
def root():
    return redirect(url_for("scamcalls"))


@app.route("/scamcalls", methods=["GET"])
def scamcalls():
    return render_template("scamcalls.html", is_admin=_admin_authenticated())


@app.route("/scamcalls/history", methods=["GET"])
def scamcalls_history():
    return render_template("history.html")


@app.route("/scamcalls/speech", methods=["GET"])
def scamcalls_speech():
    return render_template("speech.html")


@app.route("/scamcalls/messages", methods=["GET"])
def scamcalls_messages():
    return render_template("messages.html")


# New SMS pages
@app.route("/scamtexts", methods=["GET"])
def scamtexts():
    return render_template("scamtexts.html", is_admin=_admin_authenticated())


@app.route("/scamtexts/history", methods=["GET"])
def scamtexts_history():
    return render_template("scamtexts_history.html")


def _admin_defaults() -> Tuple[str, Optional[str], bool]:
    env_user = (os.environ.get("ADMIN_USER") or "").strip()
    env_hash = (os.environ.get("ADMIN_PASSWORD_HASH") or "").strip()
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
    if not ok:
        return render_template("admin_login.html", error="Invalid credentials.")
    session["is_admin"] = True
    return redirect(url_for("scamcalls"))


@app.route("/admin/logout", methods=["GET"])
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("scamcalls"))


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
        log.exception("Failed to save env updates: %s", e)
        return Response("Failed to save settings.", status=500)


_SUPPORTED_VOICES = [
    "man", "woman", "alice",
    "Polly.Joanna", "Polly.Matthew", "Polly.Kendra", "Polly.Joey",
    "Polly.Brian", "Polly.Amy", "Polly.Emma", "Polly.Russell",
    "Polly.Nicole", "Polly.Geraint", "Polly.Lucy",
]
_SUPPORTED_LANGUAGES = [
    "en-US", "en-GB", "en-AU", "en-CA",
    "es-US", "es-ES", "fr-FR", "de-DE",
    "it-IT", "pt-BR",
]


@app.route("/api/speech-settings", methods=["GET"])
def api_speech_settings_get():
    return jsonify({
        "voices": _SUPPORTED_VOICES,
        "languages": _SUPPORTED_LANGUAGES,
        "values": {
            "tts_voice": _runtime.tts_voice,
            "tts_language": _runtime.tts_language,
            "tts_rate_percent": _runtime.tts_rate_percent,
            "tts_pitch_semitones": _runtime.tts_pitch_semitones,
            "tts_volume_db": _runtime.tts_volume_db,
            "greeting_pause_seconds": _runtime.greeting_pause_seconds,
            "response_pause_seconds": _runtime.response_pause_seconds,
            "between_phrases_pause_seconds": _runtime.between_phrases_pause_seconds,
        }
    })


@app.route("/api/speech-settings", methods=["POST"])
def api_speech_settings_post():
    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception:
        data = {}
    def clamp_int(val, lo, hi, default):
        try:
            v = int(val)
        except Exception:
            v = default
        return max(lo, min(hi, v))
    def clamp_float(val, lo, hi, default):
        try:
            v = float(val)
        except Exception:
            v = default
        v = max(lo, min(hi, v))
        return round(v, 2)
    updates: Dict[str, str] = {}
    voice = (data.get("tts_voice") or "").strip()
    if voice and voice in _SUPPORTED_VOICES:
        updates["TTS_VOICE"] = voice
    lang = (data.get("tts_language") or "").strip()
    if lang and lang in _SUPPORTED_LANGUAGES:
        updates["TTS_LANGUAGE"] = lang
    updates["TTS_RATE_PERCENT"] = str(clamp_int(data.get("tts_rate_percent"), 50, 200, _runtime.tts_rate_percent))
    updates["TTS_PITCH_SEMITONES"] = str(clamp_int(data.get("tts_pitch_semitones"), -12, 12, _runtime.tts_pitch_semitones))
    updates["TTS_VOLUME_DB"] = str(clamp_int(data.get("tts_volume_db"), -6, 6, _runtime.tts_volume_db))
    updates["GREETING_PAUSE_SECONDS"] = str(clamp_float(data.get("greeting_pause_seconds"), 0.0, 5.0, _runtime.greeting_pause_seconds))
    updates["RESPONSE_PAUSE_SECONDS"] = str(clamp_float(data.get("response_pause_seconds"), 0.0, 5.0, _runtime.response_pause_seconds))
    updates["BETWEEN_PHRASES_PAUSE_SECONDS"] = str(clamp_float(
        data.get("between_phrases_pause_seconds") if "between_phrases_pause_seconds" in data else data.get("between_phrases_pauses_seconds"),
        0.0, 5.0, _runtime.between_phrases_pause_seconds))
    _apply_env_updates(updates)
    return jsonify(ok=True, values={
        "tts_voice": _runtime.tts_voice,
        "tts_language": _runtime.tts_language,
        "tts_rate_percent": _runtime.tts_rate_percent,
        "tts_pitch_semitones": _runtime.tts_pitch_semitones,
        "tts_volume_db": _runtime.tts_volume_db,
        "greeting_pause_seconds": _runtime.greeting_pause_seconds,
        "response_pause_seconds": _runtime.response_pause_seconds,
        "between_phrases_pause_seconds": _runtime.between_phrases_pause_seconds,
    })


def _load_user_messages_from_disk() -> List[str]:
    if not MESSAGES_FILE.exists():
        return []
    try:
        raw = json.loads(MESSAGES_FILE.read_text(encoding="utf-8"))
        items = raw.get("messages", []) if isinstance(raw, dict) else raw
        out: List[str] = []
        for s in items:
            if isinstance(s, str):
                t = s.strip()
                if t:
                    out.append(t)
        return out[:10]
    except Exception:
        return []


def _persist_user_messages_to_disk(msgs: List[str]) -> None:
    try:
        MESSAGES_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {"messages": msgs[:10]}
        MESSAGES_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        log.error("Failed to persist user messages: %s", e)


def _init_user_messages() -> None:
    global _USER_MESSAGES
    with _USER_MESSAGES_LOCK:
        _USER_MESSAGES = _load_user_messages_from_disk()


_init_user_messages()


@app.route("/api/messages", methods=["GET"])
def api_messages_get():
    with _USER_MESSAGES_LOCK:
        msgs = list(_USER_MESSAGES)
    return jsonify({"messages": msgs})


@app.route("/api/messages", methods=["POST"])
def api_messages_post():
    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception:
        data = {}
    items = data.get("messages")
    if not isinstance(items, list):
        return Response("Invalid payload.", status=400)
    cleaned: List[str] = []
    for s in items:
        if not isinstance(s, str):
            continue
        t = s.strip()
        if not t:
            continue
        cleaned.append(t)
        if len(cleaned) >= 10:
            break
    with _USER_MESSAGES_LOCK:
        global _USER_MESSAGES
        _USER_MESSAGES = cleaned
    _persist_user_messages_to_disk(cleaned)
    return jsonify(ok=True, messages=cleaned)


def _say_with_prosody(vr: VoiceResponse, text: str, voice: str, language: str) -> None:
    text = text or ""
    try:
        if voice.startswith("Polly.") and (
            _runtime.tts_rate_percent != 100 or _runtime.tts_pitch_semitones != 0 or _runtime.tts_volume_db != 0
        ):
            rate = f"{_runtime.tts_rate_percent}%"
            pitch_sign = "+" if _runtime.tts_pitch_semitones >= 0 else ""
            pitch = f"{pitch_sign}{_runtime.tts_pitch_semitones}st"
            vol_sign = "+" if _runtime.tts_volume_db >= 0 else ""
            volume = f"{vol_sign}{_runtime.tts_volume_db}dB"
            ssml = f"<speak><prosody rate='{rate}' pitch='{pitch}' volume='{volume}'>{_xml_escape(text)}</prosody></speak>"
            vr.say(ssml, voice=voice, language=language)
            return
        vr.say(text, voice=voice, language=language)
    except Exception:
        vr.say(text, voice=voice, language=language)


def _pick_user_message() -> Optional[str]:
    with _USER_MESSAGES_LOCK:
        if not _USER_MESSAGES:
            return None
        return random.choice(_USER_MESSAGES)


def _build_opening_lines_for_sid(call_sid: str) -> List[str]:
    one = _pop_one_shot_opening()
    if one:
        lines = [one]
    else:
        pick = _pick_user_message()
        if pick:
            lines = [pick]
        else:
            params = _get_params_for_sid(call_sid)
            base_dialog = _get_dialog_lines(params.dialog_idx)
            first = base_dialog[0] if base_dialog else "Hello."
            lines = [first]
    if _runtime.company_name:
        lines.append(f"This is {_runtime.company_name}.")
    if _runtime.topic:
        lines.append(f"I am calling about {_runtime.topic}.")
    return [ln for ln in lines if ln]


@app.route("/voice", methods=["POST", "GET"])
def voice_entrypoint():
    if VoiceResponse is None:
        return Response("Server missing Twilio TwiML library.", status=500)
    vr = VoiceResponse()
    call_sid = request.values.get("CallSid", "") or None
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
    if _runtime.enable_media_streams and Start is not None and Stream is not None and _runtime.public_base_url:
        try:
            start = Start()
            ws_base = _runtime.public_base_url.replace("http:", "ws:").replace("https:", "wss:")
            start.stream(url=f"{ws_base}/media-in", track="inbound_track")
            start.stream(url=f"{ws_base}/media-out", track="outbound_track")
            vr.append(start)
        except Exception:
            pass
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
        return Response("Server missing Twilio TwiML library.", status=500)
    vr = VoiceResponse()
    call_sid = request.values.get("CallSid", "") or ""
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
    if speech_text:
        _append_transcript(call_sid, "Callee", speech_text, is_final=True)
    params = _get_params_for_sid(call_sid)
    opening_lines = _build_opening_lines_for_sid(call_sid)
    for i, line in enumerate(opening_lines):
        _append_transcript(call_sid, "Assistant", line, is_final=True)
        _say_with_prosody(vr, line, voice=params.voice, language=_runtime.tts_language)
        if i < len(opening_lines) - 1 and _runtime.greeting_pause_seconds > 0:
            vr.pause(length=_runtime.greeting_pause_seconds)
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
    _say_with_prosody(vr, "Goodbye.", voice=params.voice, language=_runtime.tts_language)
    vr.hangup()
    return Response(str(vr), status=200, mimetype="text/xml")


@app.route("/dialog", methods=["POST"])
def dialog():
    if VoiceResponse is None:
        return Response("Server missing Twilio TwiML library.", status=500)
    vr = VoiceResponse()
    call_sid = request.values.get("CallSid", "") or ""
    turn = _parse_int(request.args.get("turn"), 1)
    speech_text = (request.values.get("SpeechResult") or "").strip()
    if speech_text:
        _append_transcript(call_sid, "Callee", speech_text, is_final=True)
    if _runtime.response_pause_seconds > 0:
        try:
            vr.pause(length=_runtime.response_pause_seconds)
        except Exception:
            pass
    params = _get_params_for_sid(call_sid)
    reply_lines = _compose_assistant_reply(call_sid, turn)
    for i, line in enumerate(reply_lines):
        _append_transcript(call_sid, "Assistant", line, is_final=True)
        _say_with_prosody(vr, line, voice=params.voice, language=_runtime.tts_language)
        if i < len(reply_lines) - 1 and _runtime.between_phrases_pause_seconds > 0:
            vr.pause(length=_runtime.between_phrases_pause_seconds)
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
        _say_with_prosody(vr, "Goodbye.", voice=params.voice, language=_runtime.tts_language)
        vr.hangup()
    else:
        _say_with_prosody(vr, "Goodbye.", voice=params.voice, language=_runtime.tts_language)
        vr.hangup()
    return Response(str(vr), status=200, mimetype="text/xml")


@app.route("/transcribe-partial", methods=["POST"])
def transcribe_partial():
    call_sid = request.values.get("CallSid", "") or ""
    stage = request.args.get("stage") or "unknown"
    seq = request.args.get("seq") or ""
    _set_current_call_sid(call_sid or _get_current_call_sid())
    part = (request.values.get("UnstableSpeechResult") or request.values.get("SpeechResult") or "").strip()
    if part:
        _append_transcript(call_sid, "Callee", part, is_final=False)
    return ("", 204)


@app.route("/status", methods=["POST"])
def status_callback():
    call_sid = request.values.get("CallSid", "") or ""
    call_status = (request.values.get("CallStatus") or "").lower()
    duration = request.values.get("CallDuration") or ""
    to_n = request.values.get("To") or ""
    from_n = request.values.get("From") or ""
    now = int(time.time())
    if call_status in ("initiated", "ringing", "in-progress", "answered"):
        if call_sid:
            _set_current_call_sid(call_sid)
            _init_call_meta_if_absent(call_sid, to=to_n, from_n=from_n, started_at=now)
        _clear_outgoing_pending()
        _clear_last_dial_error()
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


# WebSockets (optional) for media streams to browser
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


if Sock is not None:
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
        finally:
            pass

    @_sock.route("/media-out")
    def media_out(ws):  # type: ignore
        try:
            while True:
                msg = ws.receive()
                if msg is None:
                    break
        finally:
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
        finally:
            with _AUDIO_CLIENTS_LOCK:
                _AUDIO_CLIENTS.discard(ws)


_active_tunnel_url: Optional[str] = None


def _start_ngrok_if_enabled() -> None:
    global _active_tunnel_url
    if not _runtime.use_ngrok:
        return
    if ngrok_lib is None:
        return
    try:
        if _active_tunnel_url:
            return
        port = _runtime.flask_port or 8080
        tun = ngrok_lib.connect(addr=port, proto="http")
        _active_tunnel_url = tun.public_url  # type: ignore
        os.environ["PUBLIC_BASE_URL"] = _active_tunnel_url
        _runtime.public_base_url = _active_tunnel_url
    except Exception as e:
        log.error("Failed to start ngrok: %s", e)


@atexit.register
def _shutdown_ngrok():
    try:
        if ngrok_lib is not None:
            ngrok_lib.kill()
    except Exception:
        pass


def _handle_termination(signum, frame):
    try:
        _stop_requested.set()
        _sms_stop_requested.set()
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
    _maybe_start_sms_thread()


@app.route("/api/call-now", methods=["POST"])
def api_call_now():
    ready, reasons = _diagnostics_ready_to_call()
    if not ready:
        return jsonify(ok=False, reason="not_ready", message="Service not ready for outbound calls.", reasons=reasons), 400
    if not _within_active_window(_now_local()):
        return jsonify(ok=False, reason="outside_active_window"), 200
    if not _runtime.to_number:
        return jsonify(ok=False, reason="missing_destination"), 400
    if _get_current_call_sid() is not None:
        return jsonify(ok=False, reason="already_in_progress"), 409
    if _is_outgoing_pending():
        return jsonify(ok=False, reason="pending"), 409
    now = int(time.time())
    can, wait_s = _can_attempt(now, _runtime.to_number)
    if not can:
        return jsonify(ok=False, reason="cap_reached", wait_seconds=wait_s), 429
    direct = _parse_bool(os.environ.get("DIRECT_DIAL_ON_TRIGGER"), True)
    if direct:
        ok = _place_call_now()
        if ok:
            return jsonify(ok=True, started=True)
        with _LAST_DIAL_ERROR_LOCK:
            err = _LAST_DIAL_ERROR.get("message") if _LAST_DIAL_ERROR else "Twilio call placement failed."
        return jsonify(ok=False, reason="twilio_error", message=err), 502
    _mark_outgoing_pending()
    _manual_call_requested.set()
    return jsonify(ok=True, queued=True)


@app.route("/api/status", methods=["GET"])
def api_status():
    now = int(time.time())
    with _next_call_epoch_s_lock:
        seconds_until_next = int(max(0, _next_call_epoch_s - now)) if _next_call_epoch_s is not None else None
        interval_total = int(_interval_total_seconds) if _interval_total_seconds is not None else None
    attempts_last_hour = 0
    attempts_last_day = 0
    if _runtime.to_number:
        with _attempts_lock:
            lst = list(_dest_attempts.get(_runtime.to_number, []))
        cutoff_h = now - 3600
        cutoff_d = now - 24 * 3600
        attempts_last_hour = sum(1 for t in lst if t >= cutoff_h)
        attempts_last_day = sum(1 for t in lst if t >= cutoff_d)
    can_attempt_now = True
    wait_seconds_if_capped = 0
    if _runtime.to_number:
        can_attempt_now, wait_seconds_if_capped = _can_attempt(now, _runtime.to_number)
    call_sid = _get_current_call_sid()
    call_in_progress = bool(call_sid)
    within_active = _within_active_window(_now_local())
    last_err = None
    with _LAST_DIAL_ERROR_LOCK:
        if _LAST_DIAL_ERROR:
            last_err = dict(_LAST_DIAL_ERROR)
    payload = {
        "call_in_progress": call_in_progress,
        "call_sid": call_sid or "",
        "within_active_window": within_active,
        "seconds_until_next": seconds_until_next if seconds_until_next is not None else None,
        "interval_total_seconds": interval_total if interval_total is not None else None,
        "attempts_last_hour": attempts_last_hour,
        "attempts_last_day": attempts_last_day,
        "hourly_max_attempts": _runtime.hourly_max_attempts,
        "daily_max_attempts": _runtime.daily_max_attempts,
        "can_attempt_now": bool(can_attempt_now),
        "wait_seconds_if_capped": int(wait_seconds_if_capped) if wait_seconds_if_capped else 0,
        "to_number": _runtime.to_number or "",
        "from_number": _runtime.from_number or "",
        "from_numbers": list(_runtime.from_numbers or []),
        "public_base_url": _runtime.public_base_url or "",
        "active_hours_local": _runtime.active_hours_local or "",
        "last_error": last_err,
    }
    return jsonify(payload)


@app.route("/api/live", methods=["GET"])
def api_live():
    call_sid = _get_current_call_sid()
    in_progress = bool(call_sid)
    with _TRANSCRIPTS_LOCK:
        transcript = list(_TRANSCRIPTS.get(call_sid, [])) if call_sid else []
    return jsonify({
        "in_progress": in_progress,
        "call_sid": call_sid or "",
        "media_streams_enabled": bool(_runtime.enable_media_streams),
        "transcript": transcript,
    })


@app.route("/api/history", methods=["GET"])
def api_history():
    try:
        calls = _scan_history_summaries(limit=1000)
        return jsonify({"calls": calls})
    except Exception:
        return jsonify({"calls": []})


@app.route("/api/history/<sid>", methods=["GET"])
def api_history_get(sid: str):
    d = _load_call_history(sid)
    if not d:
        return Response("Not found", status=404)
    return jsonify(d)


@app.route("/api/metrics", methods=["GET"])
def api_metrics():
    try:
        metrics = _compute_history_metrics()
        return jsonify(metrics)
    except Exception:
        return jsonify({"total_calls": 0, "total_duration_seconds": 0, "average_call_seconds": 0})


# One-shot opening for calls (mirrors existing behavior)
_ONE_SHOT_OPENING_LOCK = threading.Lock()
_ONE_SHOT_OPENING: Optional[str] = None


def _pop_one_shot_opening() -> Optional[str]:
    global _ONE_SHOT_OPENING
    with _ONE_SHOT_OPENING_LOCK:
        s = _ONE_SHOT_OPENING
        _ONE_SHOT_OPENING = None
        return s


@app.route("/api/next-opening", methods=["POST"])
def next_opening():
    try:
        data = request.get_json(force=True, silent=True) or {}
        text = (data.get("text") or "").strip()
        if not text:
            return jsonify({"ok": False, "error": "Empty text"}), 400
        if len(text) > 150:
            return jsonify({"ok": False, "error": "Max 150 characters"}), 400
        clean = "".join(ch for ch in text if ch >= " ").strip()
        if not clean:
            return jsonify({"ok": False, "error": "Invalid content"}), 400
        with _ONE_SHOT_OPENING_LOCK:
            global _ONE_SHOT_OPENING
            _ONE_SHOT_OPENING = clean
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# ---------------------------
# SMS: persistence, scheduler, APIs
# ---------------------------

def _persist_sms_history(message_sid: str, meta: Dict[str, Any]) -> None:
    if not message_sid:
        return
    payload = {
        "sid": message_sid,
        "meta": {
            "to": meta.get("to", ""),
            "from": meta.get("from", ""),
            "body": meta.get("body", ""),
            "status": meta.get("status", ""),
            "error": meta.get("error", ""),
            "created_at": meta.get("created_at"),
            "updated_at": meta.get("updated_at"),
            "delivered_at": meta.get("delivered_at"),
        },
        "events": meta.get("events", []),
    }
    try:
        p = SMS_HISTORY_DIR / f"{message_sid}.json"
        p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        log.error("Failed to persist SMS history: %s", e)


def _load_sms_history(sid: str) -> Optional[Dict[str, Any]]:
    p = SMS_HISTORY_DIR / f"{sid}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _scan_sms_history_summaries(limit: int = 1000) -> List[Dict[str, Any]]:
    items: List[Tuple[float, Dict[str, Any]]] = []
    try:
        for f in SMS_HISTORY_DIR.glob("*.json"):
            try:
                d = json.loads(f.read_text(encoding="utf-8"))
                meta = d.get("meta", {}) or {}
                out = {
                    "sid": d.get("sid") or "",
                    "to": meta.get("to") or "",
                    "from": meta.get("from") or "",
                    "status": meta.get("status") or "",
                    "body_preview": (meta.get("body") or "")[:120],
                    "created_at": meta.get("created_at"),
                    "updated_at": meta.get("updated_at"),
                }
                items.append((f.stat().st_mtime, out))
            except Exception:
                continue
    except Exception:
        pass
    items.sort(key=lambda t: t[0], reverse=True)
    return [x[1] for x in items[:limit]]


def _compute_sms_metrics() -> Dict[str, int]:
    summaries = _scan_sms_history_summaries(limit=1000000)
    total = len(summaries)
    delivered = 0
    failed = 0
    for s in summaries:
        st = (s.get("status") or "").lower()
        if st in ("delivered", "sent"):
            delivered += 1
        elif st in ("failed", "undelivered"):
            failed += 1
    return {
        "total_messages": total,
        "delivered_messages": delivered,
        "failed_messages": failed,
    }


_SMS_ATTEMPTS_LOCK = threading.Lock()
_SMS_DEST_ATTEMPTS: Dict[str, List[float]] = {}


def _sms_prune_attempts(now_ts: int, to_number: str) -> None:
    with _SMS_ATTEMPTS_LOCK:
        lst = _SMS_DEST_ATTEMPTS.get(to_number, [])
        cutoff = now_ts - 24 * 3600
        _SMS_DEST_ATTEMPTS[to_number] = [t for t in lst if t >= cutoff]


def _sms_note_attempt(now_ts: float, to_number: str) -> None:
    with _SMS_ATTEMPTS_LOCK:
        _SMS_DEST_ATTEMPTS.setdefault(to_number, []).append(now_ts)


def _sms_can_attempt(now_ts: int, to_number: str) -> Tuple[bool, int]:
    _sms_prune_attempts(now_ts, to_number)
    with _SMS_ATTEMPTS_LOCK:
        lst = _SMS_DEST_ATTEMPTS.get(to_number, [])
        last_hour = [t for t in lst if t >= now_ts - 3600]
        if len(last_hour) >= _sms_runtime.hourly_max_attempts:
            oldest = min(last_hour) if last_hour else now_ts
            wait = max(1, (int(oldest) + 3600) - now_ts)
            return False, wait
        if len(lst) >= _sms_runtime.daily_max_attempts:
            return False, 3600
    return True, 0


def _sms_within_active_window(now_local: datetime) -> bool:
    hours = (_sms_runtime.active_hours_local or "").strip() or _runtime.active_hours_local or "09:00-18:00"
    try:
        start_str, end_str = hours.split("-", 1)
        sh, sm = [int(x) for x in start_str.split(":")]
        eh, em = [int(x) for x in end_str.split(":")]
    except Exception:
        sh, sm, eh, em = 9, 0, 18, 0
    wd_map = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    today = wd_map[now_local.weekday()]
    days = _sms_runtime.active_days or _runtime.active_days
    if days and today not in days:
        return False
    t_minutes = now_local.hour * 60 + now_local.minute
    start_m = sh * 60 + sm
    end_m = eh * 60 + em
    if start_m <= end_m:
        return start_m <= t_minutes <= end_m
    return t_minutes >= start_m or t_minutes <= end_m


_SMS_ONE_SHOT_OPENING_LOCK = threading.Lock()
_SMS_ONE_SHOT_OPENING: Optional[str] = None


def _sms_pop_one_shot_opening() -> Optional[str]:
    global _SMS_ONE_SHOT_OPENING
    with _SMS_ONE_SHOT_OPENING_LOCK:
        s = _SMS_ONE_SHOT_OPENING
        _SMS_ONE_SHOT_OPENING = None
        return s


def _sms_choose_from_number() -> Optional[str]:
    if _sms_runtime.from_numbers:
        return random.choice(_sms_runtime.from_numbers)
    if _sms_runtime.from_number:
        return _sms_runtime.from_number
    return _choose_from_number()


def _compose_sms_body() -> str:
    line = _sms_pop_one_shot_opening()
    if line:
        return line.strip()[:500]
    if _sms_runtime.template:
        try:
            txt = _sms_runtime.template.format(company_name=_runtime.company_name or "", topic=_runtime.topic or "")
        except Exception:
            txt = _sms_runtime.template
        return str(txt)[:500]
    pick = _pick_user_message()
    if pick:
        return pick[:500]
    parts = []
    if _runtime.company_name:
        parts.append(f"{_runtime.company_name}:")
    if _runtime.topic:
        parts.append(f"Regarding {_runtime.topic}.")
    parts.append("Please reply when available.")
    return " ".join(parts)[:500]


_sms_thread: Optional[threading.Thread] = None
_sms_stop_requested = threading.Event()
_sms_manual_send_requested = threading.Event()
_NEXT_SMS_EPOCH_LOCK = threading.Lock()
_next_sms_epoch_s: Optional[int] = None
_sms_interval_total_seconds: Optional[int] = None


def _compute_next_sms_interval_seconds() -> int:
    lo = max(60, int(_sms_runtime.min_interval_seconds))
    hi = max(lo, int(_sms_runtime.max_interval_seconds))
    if lo == hi:
        return lo
    return random.randint(lo, hi)


def _initialize_sms_schedule_if_needed(now: int) -> None:
    global _next_sms_epoch_s, _sms_interval_total_seconds
    with _NEXT_SMS_EPOCH_LOCK:
        if _next_sms_epoch_s is None:
            _sms_interval_total_seconds = _compute_next_sms_interval_seconds()
            _next_sms_epoch_s = now + int(_sms_interval_total_seconds or 0)


def _reset_sms_schedule_after_completion(now: int) -> None:
    global _next_sms_epoch_s, _sms_interval_total_seconds
    with _NEXT_SMS_EPOCH_LOCK:
        interval = _compute_next_sms_interval_seconds()
        _sms_interval_total_seconds = interval
        _next_sms_epoch_s = now + int(interval)


def _send_sms_now() -> Tuple[bool, str, Optional[str]]:
    if not _sms_runtime.enabled:
        return (False, "SMS scheduler disabled", None)
    client = _ensure_twilio_client()
    if not client:
        return (False, "Twilio client missing", None)
    to_n = _sms_runtime.to_number or ""
    from_n = _sms_choose_from_number() or ""
    if not to_n or not from_n:
        return (False, "Missing SMS TO or FROM", None)
    if not _sms_within_active_window(_now_local()):
        return (False, "Outside active SMS window", None)
    now = int(time.time())
    ok_cap, wait_s = _sms_can_attempt(now, to_n)
    if not ok_cap:
        return (False, f"Cap reached, wait {wait_s}s", None)
    body = _compose_sms_body()
    try:
        kwargs: Dict[str, Any] = dict(
            to=to_n,
            from_=from_n,
            body=body,
        )
        if _runtime.public_base_url:
            kwargs["status_callback"] = f"{_runtime.public_base_url}/sms/status"  # type: ignore
        msg = client.messages.create(**kwargs)  # type: ignore
        sid = getattr(msg, "sid", "") or ""
        meta = {
            "to": to_n,
            "from": from_n,
            "body": body,
            "status": getattr(msg, "status", "") or "queued",
            "error": "",
            "created_at": now,
            "updated_at": now,
            "delivered_at": None,
            "events": [{"t": now, "event": "created", "status": getattr(msg, "status", "")}],
        }
        _persist_sms_history(sid, meta)
        _sms_note_attempt(time.time(), to_n)
        return (True, sid, None)
    except Exception as e:
        sid = f"ERR-{int(time.time())}"
        meta = {
            "to": to_n,
            "from": from_n,
            "body": body,
            "status": "failed",
            "error": str(e),
            "created_at": now,
            "updated_at": now,
            "delivered_at": None,
            "events": [{"t": now, "event": "error", "status": "failed", "error": str(e)}],
        }
        _persist_sms_history(sid, meta)
        return (False, "twilio_error", str(e))


def _sms_loop() -> None:
    while not _sms_stop_requested.is_set():
        try:
            now = int(time.time())
            if not _sms_runtime.enabled:
                time.sleep(1.0)
                continue
            _initialize_sms_schedule_if_needed(now)
            if _sms_manual_send_requested.is_set():
                _sms_manual_send_requested.clear()
                if _sms_within_active_window(_now_local()):
                    _send_sms_now()
                _reset_sms_schedule_after_completion(now)
            with _NEXT_SMS_EPOCH_LOCK:
                ready = (_next_sms_epoch_s is not None and now >= _next_sms_epoch_s)
            if ready:
                if _sms_within_active_window(_now_local()):
                    _send_sms_now()
                _reset_sms_schedule_after_completion(now)
            time.sleep(0.2)
        except Exception:
            time.sleep(0.5)


def _maybe_start_sms_thread() -> None:
    global _sms_thread
    if not _sms_runtime.enabled:
        return
    if _sms_thread is None or not _sms_thread.is_alive():
        _sms_stop_requested.clear()
        _sms_thread = threading.Thread(target=_sms_loop, name="sms-thread", daemon=True)
        _sms_thread.start()


# SMS APIs

@app.route("/api/texts/status", methods=["GET"])
def api_texts_status():
    now = int(time.time())
    with _NEXT_SMS_EPOCH_LOCK:
        seconds_until_next = int(max(0, _next_sms_epoch_s - now)) if _next_sms_epoch_s is not None else None
        interval_total = int(_sms_interval_total_seconds) if _sms_interval_total_seconds is not None else None
    attempts_last_hour = 0
    attempts_last_day = 0
    if _sms_runtime.to_number:
        with _SMS_ATTEMPTS_LOCK:
            lst = list(_SMS_DEST_ATTEMPTS.get(_sms_runtime.to_number, []))
        cutoff_h = now - 3600
        cutoff_d = now - 24 * 3600
        attempts_last_hour = sum(1 for t in lst if t >= cutoff_h)
        attempts_last_day = sum(1 for t in lst if t >= cutoff_d)
    can_attempt_now = True
    wait_seconds_if_capped = 0
    if _sms_runtime.to_number:
        can_attempt_now, wait_seconds_if_capped = _sms_can_attempt(now, _sms_runtime.to_number)
    within_active = _sms_within_active_window(_now_local())
    payload = {
        "sms_enabled": bool(_sms_runtime.enabled),
        "within_active_window": within_active,
        "seconds_until_next": seconds_until_next if seconds_until_next is not None else None,
        "interval_total_seconds": interval_total if interval_total is not None else None,
        "attempts_last_hour": attempts_last_hour,
        "attempts_last_day": attempts_last_day,
        "hourly_max_attempts": _sms_runtime.hourly_max_attempts,
        "daily_max_attempts": _sms_runtime.daily_max_attempts,
        "can_attempt_now": bool(can_attempt_now),
        "wait_seconds_if_capped": int(wait_seconds_if_capped) if wait_seconds_if_capped else 0,
        "to_number": _sms_runtime.to_number or "",
        "from_number": _sms_runtime.from_number or "",
        "from_numbers": list(_sms_runtime.from_numbers or []),
        "template_preview": (_sms_runtime.template or _compose_sms_body()),
        "public_base_url": _runtime.public_base_url or "",
        "active_hours_local": (_sms_runtime.active_hours_local or _runtime.active_hours_local or ""),
    }
    return jsonify(payload)


@app.route("/api/texts/send-now", methods=["POST"])
def api_texts_send_now():
    if not _sms_runtime.enabled:
        return jsonify(ok=False, reason="disabled", message="SMS scheduler disabled"), 400
    ok, sid_or_reason, err = _send_sms_now()
    if ok:
        return jsonify(ok=True, message_sid=sid_or_reason)
    status = 502 if sid_or_reason == "twilio_error" else 400
    return jsonify(ok=False, reason=sid_or_reason, error=err or ""), status


@app.route("/api/texts/next-opening", methods=["POST"])
def api_texts_next_opening():
    try:
        data = request.get_json(force=True, silent=True) or {}
        text = (data.get("text") or "").strip()
        if not text:
            return jsonify({"ok": False, "error": "Empty text"}), 400
        if len(text) > 500:
            return jsonify({"ok": False, "error": "Max 500 characters"}), 400
        safe = "".join(ch for ch in text if ch >= " " or ch == "\n").strip()
        if not safe:
            return jsonify({"ok": False, "error": "Invalid content"}), 400
        with _SMS_ONE_SHOT_OPENING_LOCK:
            global _SMS_ONE_SHOT_OPENING
            _SMS_ONE_SHOT_OPENING = safe
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/texts/history", methods=["GET"])
def api_texts_history():
    try:
        msgs = _scan_sms_history_summaries(limit=1000)
        return jsonify({"messages": msgs})
    except Exception:
        return jsonify({"messages": []})


@app.route("/api/texts/history/<sid>", methods=["GET"])
def api_texts_history_get(sid: str):
    d = _load_sms_history(sid)
    if not d:
        return Response("Not found", status=404)
    meta = d.get("meta", {})
    meta["to_masked"] = _mask_phone(meta.get("to"))
    meta["from_masked"] = _mask_phone(meta.get("from"))
    d["meta"] = meta
    return jsonify(d)


@app.route("/api/texts/metrics", methods=["GET"])
def api_texts_metrics():
    try:
        m = _compute_sms_metrics()
        return jsonify(m)
    except Exception:
        return jsonify({"total_messages": 0, "delivered_messages": 0, "failed_messages": 0})


@app.route("/api/texts/export.csv", methods=["GET"])
def api_texts_export_csv():
    try:
        rows = _scan_sms_history_summaries(limit=1000000)
        headers = ["sid", "created_at", "updated_at", "to", "from", "status", "body_preview"]
        import io
        from flask import send_file
        output = io.StringIO()
        w = csv.DictWriter(output, fieldnames=headers)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in headers})
        mem = io.BytesIO(output.getvalue().encode("utf-8"))
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=f"scamtexts_{ts}.csv")
    except Exception:
        return Response("Failed to export CSV", status=500)


@app.route("/api/texts/export.json", methods=["GET"])
def api_texts_export_json():
    try:
        rows = _scan_sms_history_summaries(limit=1000000)
        return jsonify({"ok": True, "rows": rows})
    except Exception:
        return jsonify({"ok": False, "rows": []})


@app.route("/sms/status", methods=["POST"])
def sms_status_callback():
    sid = request.values.get("MessageSid", "") or ""
    status = (request.values.get("MessageStatus") or "").lower()
    to_n = request.values.get("To") or ""
    from_n = request.values.get("From") or ""
    now = int(time.time())
    try:
        d = _load_sms_history(sid) or {"sid": sid, "meta": {"to": to_n, "from": from_n, "body": "", "status": "", "error": "", "created_at": now, "updated_at": now, "delivered_at": None}, "events": []}
        meta = d.get("meta", {})
        meta["status"] = status or meta.get("status") or ""
        meta["updated_at"] = now
        if status == "delivered":
            meta["delivered_at"] = now
        events = d.get("events", [])
        events.append({"t": now, "event": "status", "status": status})
        d["meta"] = meta
        d["events"] = events
        _persist_sms_history(sid, {**meta, "events": events})
    except Exception as e:
        log.exception("Failed processing SMS status callback: %s", e)
    return ("", 204)


@app.route("/health", methods=["GET"])
def health():
    return jsonify(ok=True, ts=int(time.time()))


def main():
    acc = os.environ.get("TWILIO_ACCOUNT_SID", "")
    if acc:
        log.info("Twilio Account SID present (masked): %s", _mask_sid(acc))
    _log_runtime_summary(context="startup")
    _start_ngrok_if_enabled()
    _start_background_threads()
    host = _runtime.flask_host or os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(_runtime.flask_port or _parse_int(os.environ.get("FLASK_PORT"), 8080))
    debug = bool(_runtime.flask_debug or _parse_bool(os.environ.get("FLASK_DEBUG"), False))
    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    main()
