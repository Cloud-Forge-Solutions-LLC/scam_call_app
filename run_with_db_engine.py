#!/usr/bin/env python3
"""
Bootstrap to run scam_call_app with:
- SQLite history (via existing run_with_db monkey patches).
- Conversation engine integration (toggle and attitude slider).
- Non-invasive overrides: original behavior is preserved when engine is disabled.

Run:
  python3 run_with_db_and_engine.py

Settings persist to:
  data/conversation_settings.json

API:
  GET  /api/conversation/settings
  POST /api/conversation/settings
      body: {
        "use_engine_calls": bool,
        "use_engine_texts": bool,
        "attitude_level": int (1..5),
        "enable_explicit": bool (optional; default false)
      }
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, Optional

# Initialize DB patches first
import run_with_db as db_bootstrap  # noqa: F401

# Import main app
import twilio_outbound_call as appmod  # type: ignore

from flask import request, Response, jsonify, url_for, render_template
from ultrafast_convo_engine import UltraFastConversationEngine

app = appmod.app

# ------------- Settings persistence -------------

_SETTINGS_LOCK = threading.RLock()
_SETTINGS_PATH = os.path.abspath(os.path.join("data", "conversation_settings.json"))
_DEFAULT_SETTINGS: Dict[str, Any] = {
    "use_engine_calls": False,
    "use_engine_texts": False,
    "attitude_level": 2,
    "enable_explicit": False,
}

def _ensure_data_dir() -> None:
    d = os.path.dirname(_SETTINGS_PATH)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)

def _load_settings() -> Dict[str, Any]:
    with _SETTINGS_LOCK:
        try:
            if os.path.isfile(_SETTINGS_PATH):
                with open(_SETTINGS_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    out = dict(_DEFAULT_SETTINGS)
                    if isinstance(data, dict):
                        out.update({k: data.get(k, out[k]) for k in out.keys()})
                    return out
        except Exception:
            pass
        return dict(_DEFAULT_SETTINGS)

def _save_settings(data: Dict[str, Any]) -> None:
    with _SETTINGS_LOCK:
        _ensure_data_dir()
        clean = dict(_DEFAULT_SETTINGS)
        for k in clean.keys():
            if k in data:
                clean[k] = data[k]
        with open(_SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(clean, f, ensure_ascii=False, indent=2)

# ------------- Engine management -------------

_ENGINE_LOCK = threading.RLock()
_ENGINE_BY_SID: Dict[str, UltraFastConversationEngine] = {}

def _get_engine_for_sid(call_sid: str, settings: Dict[str, Any]) -> UltraFastConversationEngine:
    with _ENGINE_LOCK:
        eng = _ENGINE_BY_SID.get(call_sid)
        if eng is None:
            eng = UltraFastConversationEngine(
                attitude_level=int(settings.get("attitude_level", 2) or 2),
                max_response_chars=160,
                enable_explicit=bool(settings.get("enable_explicit", False)),
            )
            _ENGINE_BY_SID[call_sid] = eng
        else:
            # Keep level in sync if updated mid-call
            eng.set_attitude_level(int(settings.get("attitude_level", 2) or 2))
        return eng

def _dispose_engine_for_sid(call_sid: str) -> None:
    with _ENGINE_LOCK:
        _ENGINE_BY_SID.pop(call_sid, None)

# ------------- API routes -------------

@app.route("/api/conversation/settings", methods=["GET"])
def api_conversation_settings_get():
    s = _load_settings()
    return jsonify({"ok": True, "values": s})

@app.route("/api/conversation/settings", methods=["POST"])
def api_conversation_settings_post():
    try:
        d = request.get_json(force=True, silent=False) or {}
        s = _load_settings()
        if "use_engine_calls" in d:
            s["use_engine_calls"] = bool(d["use_engine_calls"])
        if "use_engine_texts" in d:
            s["use_engine_texts"] = bool(d["use_engine_texts"])
        if "attitude_level" in d:
            try:
                lvl = int(d["attitude_level"])
                if lvl < 1: lvl = 1
                if lvl > 5: lvl = 5
                s["attitude_level"] = lvl
            except Exception:
                pass
        if "enable_explicit" in d:
            s["enable_explicit"] = bool(d["enable_explicit"])
        _save_settings(s)
        return jsonify({"ok": True, "values": s})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

# ------------- UI routes for texts (templates exist) -------------

# Only register if missing to avoid conflicts
if "scamtexts" not in app.view_functions:
    @app.route("/scamtexts", methods=["GET"])
    def scamtexts():
        appmod.log.info("GET /scamtexts")
        return render_template("scamtexts.html")

if "scamtexts_history" not in app.view_functions:
    @app.route("/scamtexts/history", methods=["GET"])
    def scamtexts_history():
        appmod.log.info("GET /scamtexts/history")
        return render_template("scamtexts_history.html")

# ------------- Monkey-patch dialog to use engine when enabled -------------

# Save original to fall back if engine disabled
_ORIG_DIALOG = app.view_functions.get("dialog")

def _dialog_with_engine():
    """
    When the engine is enabled for calls, respond to the latest SpeechResult
    using UltraFastConversationEngine and continue listening.
    Otherwise delegate to the original dialog handler.
    """
    settings = _load_settings()
    if not settings.get("use_engine_calls", False) or _ORIG_DIALOG is None:
        # Delegate to original behavior unchanged
        return _ORIG_DIALOG()

    # Engine path
    if appmod.VoiceResponse is None:
        appmod.log.error("Server missing Twilio TwiML library.")
        return Response("Server missing Twilio TwiML library.", status=500)

    vr = appmod.VoiceResponse()
    call_sid = (request.values.get("CallSid") or "").strip()
    turn = 1
    try:
        turn = int(request.args.get("turn", "1") or "1")
    except Exception:
        turn = 1

    appmod.log.info("ENGINE /dialog: CallSid=%s, turn=%s", appmod._mask_sid(call_sid), turn)

    # Record any callee speech we received
    speech_text = (request.values.get("SpeechResult") or "").strip()
    if speech_text:
        appmod._append_transcript(call_sid, "Callee", speech_text, is_final=True)

    # Generate response
    eng = _get_engine_for_sid(call_sid, settings)
    resp_text = eng.respond(speech_text or "", call_context=None)
    # Persist transcript and speak with existing prosody helper
    appmod._append_transcript(call_sid, "Assistant", resp_text, is_final=True)

    params = appmod._get_params_for_sid(call_sid)
    appmod._say_with_prosody(vr, resp_text, voice=params.voice, language=appmod._runtime.tts_language)

    # Continue listening
    next_turn = turn + 1
    g = appmod.Gather(
        input="speech",
        method="POST",
        action=url_for("dialog", turn=next_turn, _external=True),
        timeout=str(appmod._runtime.callee_silence_hangup_seconds),
        speech_timeout="auto",
        barge_in=True,
        partial_result_callback=url_for("transcribe_partial", stage="dialog", seq=next_turn, _external=True),
        partial_result_callback_method="POST",
        language=appmod._runtime.tts_language,
    )
    vr.append(g)
    return Response(str(vr), status=200, mimetype="text/xml")

# Replace the dialog view function in-place (route path stays the same)
if _ORIG_DIALOG is not None:
    app.view_functions["dialog"] = _dialog_with_engine

# Optional: clean up engines when call completes (if status handler exists)
# Try to wrap status handler to free engine state when completed
_ORIG_STATUS = app.view_functions.get("status") or app.view_functions.get("status_handler")

def _status_with_engine_cleanup():
    # Call through first
    resp = None
    fn = _ORIG_STATUS
    if fn is not None:
        resp = fn()
    try:
        call_sid = (request.values.get("CallSid") or "").strip()
        call_status = (request.values.get("CallStatus") or "").lower()
        event = (request.values.get("StatusCallbackEvent") or "").lower()
        if call_status == "completed" or event == "completed":
            _dispose_engine_for_sid(call_sid)
    except Exception:
        pass
    return resp

if _ORIG_STATUS is not None:
    endpoint = "status" if "status" in app.view_functions else "status_handler"
    app.view_functions[endpoint] = _status_with_engine_cleanup

if __name__ == "__main__":
    # Start the app the same way the main module does
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    debug = str(os.environ.get("FLASK_DEBUG", "false")).strip().lower() in {"1", "true", "yes", "on"}
    appmod.log.info("Starting Flask (engine bootstrap) on %s:%s (debug=%s)", host, port, debug)
    app.run(host=host, port=port, debug=debug)
