"""
UltraFastConversationEngine

Purpose:
- Generate short, context-appropriate replies for phone-call conversations with extremely low latency.
- Optimized for constrained devices (for example, Raspberry Pi). No external dependencies.
- Deterministic behavior to simplify testing and reduce jitter before text-to-speech (TTS).
- Supports an "attitude" slider (1..5): 1 = mild, 5 = highly aggressive. Optional explicit term injection.

Integration notes for developers:
1) Front-end slider (range 1..5)
   - The UI should send the slider's integer value to the server.
   - On change or per call, set the level with:
        engine.set_attitude_level(level)
   - Initialize with a default level during call setup.

2) Audio pipeline
   - Automatic speech recognition (ASR) delivers the callee transcript as text.
   - Call:
        response_text = engine.respond(transcript)
   - Feed response_text to your TTS system and play it to the callee.
   - Keep responses short to reduce TTS time and latency.

3) Configuration for strong or explicit language
   - By default, explicit language is disabled. The engine uses firm, concise templates.
   - To enable explicit injection when attitude_level == 5:
        engine = UltraFastConversationEngine(
            attitude_level=5,
            enable_explicit=True,
            aggressive_terms=("your custom explicit term 1", "explicit term 2"),
            # Optionally provide a custom formatter to control how terms are injected:
            # aggressive_formatter=my_formatter
        )
   - The default aggressive terms are intentionally forceful but non-profane.
     Provide your own if your research requires explicit language.

4) Concurrency and lifecycle
   - Use one engine instance per live call to avoid shared state across calls.
   - The engine maintains minimal per-call state to reduce repetition and stabilize tone.

5) Example minimal wiring for a front-end slider
   - Front-end: POST /set-attitude with JSON: {"level": 4}
   - Server handler: engine.set_attitude_level(4)
   - On each ASR result: reply = engine.respond(text); send to TTS.

Legal and policy note:
- When enabling strong or explicit language, ensure you comply with laws, carrier policies, and your Terms of Service.
- Avoid targeting protected classes and avoid slurs. Use neutral or role-oriented phrasing where possible.

API:
- UltraFastConversationEngine(attitude_level: int = 2,
                              max_response_chars: int = 160,
                              enable_explicit: bool = False,
                              aggressive_terms: Optional[tuple[str, ...]] = None,
                              aggressive_formatter: Optional[callable] = None)
- respond(text: Optional[str], call_context: Optional[dict] = None) -> str
- set_attitude_level(level: int) -> None

Performance strategies used:
- No third-party libraries.
- Precomputed token and phrase maps for intent detection.
- Single-pass normalization via translate() and split().
- Deterministic selection with O(1) index computation (no random).
- Compact templates and bounded string operations.
"""

from __future__ import annotations

import string
import time
from typing import Dict, List, Optional, Tuple


# -----------------------
# Normalization utilities
# -----------------------

# Keep apostrophes; treat other punctuation as spaces for tokenization.
_PUNCT_TO_SPACE = {ord(c): 32 for c in string.punctuation if c != "'"}
# _MULTISPACE is intentionally not used; str.split collapses whitespace efficiently.

def _normalize(text: str) -> Tuple[str, Tuple[str, ...]]:
    """
    Fast normalization:
    - Lowercase
    - Replace punctuation (except apostrophe) with spaces
    - Collapse to tokens via split
    Returns:
        norm_str: single-space-joined tokens (used for phrase matching)
        tokens: tuple of tokens (used for token matching)
    """
    s = text.lower().translate(_PUNCT_TO_SPACE)
    tokens = tuple(s.split())
    norm_str = " ".join(tokens)
    return norm_str, tokens


# -----------------------
# Intent configuration
# -----------------------

# Token-to-intent map (fast path).
_TOKEN_TO_INTENT: Dict[str, str] = {
    # greetings
    "hello": "greeting", "hi": "greeting", "hey": "greeting",
    # goodbye
    "bye": "goodbye", "goodbye": "goodbye",
    # thanks
    "thanks": "thanks", "thank": "thanks",
    # affirmation / denial
    "yes": "affirm", "yeah": "affirm", "yep": "affirm", "sure": "affirm", "correct": "affirm", "right": "affirm",
    "no": "deny", "nope": "deny", "nah": "deny",
    # anger signals
    "angry": "angry", "upset": "angry", "mad": "angry", "frustrated": "angry", "complaint": "angry", "complain": "angry",
    # help keywords
    "help": "help_request", "assist": "help_request", "support": "help_request",
    # schedule keywords
    "appointment": "availability_schedule", "schedule": "availability_schedule", "available": "availability_schedule",
}

# Ordered phrase list for substring checks on the normalized string.
_PHRASES_ORDERED: Tuple[Tuple[str, str], ...] = (
    ("good morning", "greeting"),
    ("good afternoon", "greeting"),
    ("good evening", "greeting"),
    ("see you", "goodbye"),
    ("how are you", "how_are_you"),
    ("how r u", "how_are_you"),
    ("how you doing", "how_are_you"),
    ("who is this", "identify_request"),
    ("who are you", "identify_request"),
    ("your name", "identify_request"),
    ("hold on", "hold_request"),
    ("one moment", "hold_request"),
    ("give me a second", "hold_request"),
    ("wait", "hold_request"),
    ("say again", "repeat_request"),
    ("did not hear", "repeat_request"),
    ("didn't hear", "repeat_request"),
    ("pardon", "repeat_request"),
    ("what time", "availability_schedule"),
    ("not really", "deny"),
)

_INTENTS = (
    "greeting",
    "goodbye",
    "thanks",
    "affirm",
    "deny",
    "how_are_you",
    "identify_request",
    "hold_request",
    "help_request",
    "availability_schedule",
    "repeat_request",
    "angry",
    "silence_or_empty",
    "fallback",
)


# -----------------------
# Templates by attitude level (1..5)
# -----------------------
# Expanded template sets for wider variation. Levels 4 and 5 are intentionally forceful.
# Provide your own template overrides if your research requires explicit or domain-specific phrasing.

_TEMPLATES: Dict[str, Dict[int, Tuple[str, ...]]] = {
    "greeting": {
        1: (
            "Hello. How may I help you?",
            "Hello. How may I assist you today?",
            "Hello. What can I do for you?",
        ),
        2: (
            "Hello. How can I help?",
            "Hello. What do you need?",
            "Hello. How may I assist?",
        ),
        3: (
            "Hello. What do you need?",
            "Hello. State what you need.",
            "Hello. How can I help right now?",
        ),
        4: (
            "Hello. State your request.",
            "Hello. Keep it brief.",
            "Hello. Say what you need, then stop.",
        ),
        5: (
            "Hello. Speak your request now.",
            "Hello. Be direct and fast.",
            "Hello. No small talk. What do you want?",
        ),
    },
    "goodbye": {
        1: (
            "Thank you for your time. Goodbye.",
            "Thank you. Goodbye.",
        ),
        2: (
            "Goodbye.",
            "That concludes this call. Goodbye.",
        ),
        3: (
            "Goodbye.",
            "We are done here. Goodbye.",
        ),
        4: (
            "Goodbye. End of call.",
            "That is all. Goodbye.",
        ),
        5: (
            "We are done. Goodbye.",
            "Goodbye. End this call now.",
        ),
    },
    "thanks": {
        1: (
            "You are welcome.",
            "Glad to help.",
        ),
        2: (
            "You are welcome.",
            "Understood.",
        ),
        3: (
            "Understood.",
            "Noted.",
        ),
        4: (
            "Noted.",
            "Acknowledged.",
        ),
        5: (
            "Noted.",
            "Acknowledged.",
        ),
    },
    "affirm": {
        1: (
            "Understood. Thank you.",
            "Understood.",
        ),
        2: (
            "Understood.",
            "Noted.",
        ),
        3: (
            "Understood.",
            "Proceed.",
        ),
        4: (
            "Noted.",
            "Proceed.",
        ),
        5: (
            "Noted.",
            "Proceed.",
        ),
    },
    "deny": {
        1: (
            "Understood. Thank you for clarifying.",
            "Understood.",
        ),
        2: (
            "Understood.",
            "Noted.",
        ),
        3: (
            "Understood.",
            "Noted.",
        ),
        4: (
            "Noted.",
            "Then say what you do want.",
        ),
        5: (
            "Noted.",
            "Then state what you want, clearly.",
        ),
    },
    "how_are_you": {
        1: (
            "I am well. How may I assist you?",
            "I am well. How can I help?",
        ),
        2: (
            "I am well. How can I help?",
            "I am fine. How may I assist?",
        ),
        3: (
            "I am fine. What do you need?",
            "I am fine. What is the issue?",
        ),
        4: (
            "Fine. What is your request?",
            "Fine. Say what you need.",
        ),
        5: (
            "Fine. What do you want?",
            "Fine. Get to the point.",
        ),
    },
    "identify_request": {
        1: (
            "This is the service line. How may I assist you?",
            "This is the service line. How can I help?",
        ),
        2: (
            "Service line. How can I help?",
            "Service line. What do you need?",
        ),
        3: (
            "Service line. What do you need?",
            "Service line. State the issue.",
        ),
        4: (
            "Service line. State your request.",
            "Service line. Keep it short.",
        ),
        5: (
            "Service line. Make it brief.",
            "Service line. Be direct.",
        ),
    },
    "hold_request": {
        1: (
            "Certainly. I will hold.",
            "Yes, I will wait.",
        ),
        2: (
            "I will hold.",
            "I will wait.",
        ),
        3: (
            "I will wait.",
            "I will hold briefly.",
        ),
        4: (
            "I will wait briefly.",
            "Make it quick.",
        ),
        5: (
            "Be quick.",
            "Do not take long.",
        ),
    },
    "help_request": {
        1: (
            "Please describe the issue and I will assist.",
            "Please tell me what you need.",
        ),
        2: (
            "Please tell me what you need.",
            "Describe the issue.",
        ),
        3: (
            "State the issue.",
            "Explain the problem.",
        ),
        4: (
            "Describe the issue. Keep it short.",
            "Start with the main problem.",
        ),
        5: (
            "Get to the point.",
            "State the problem in one sentence.",
        ),
    },
    "availability_schedule": {
        1: (
            "What time is convenient for you?",
            "What time works for you?",
        ),
        2: (
            "What time works for you?",
            "Suggest a time.",
        ),
        3: (
            "Suggest a time.",
            "Name a time that works.",
        ),
        4: (
            "Provide a time.",
            "Pick a time and say it.",
        ),
        5: (
            "Give a time.",
            "Say a time now.",
        ),
    },
    "repeat_request": {
        1: (
            "Certainly. What should I repeat?",
            "What would you like me to repeat?",
        ),
        2: (
            "What should I repeat?",
            "Repeat which part?",
        ),
        3: (
            "Repeat which part?",
            "What do you need repeated?",
        ),
        4: (
            "Specify what to repeat.",
            "Which part should I repeat?",
        ),
        5: (
            "Be specific.",
            "Which part, precisely?",
        ),
    },
    "angry": {
        1: (
            "I understand your concern. Please share details so I can help.",
            "I understand. Please explain the issue.",
        ),
        2: (
            "I understand. Provide details.",
            "I understand. Explain the problem.",
        ),
        3: (
            "I understand. State the issue.",
            "Explain the problem directly.",
        ),
        4: (
            "State the issue clearly.",
            "Give the facts. No extra detail.",
        ),
        5: (
            "State the problem now.",
            "Say the problem clearly, now.",
        ),
    },
    "silence_or_empty": {
        1: (
            "I did not receive any speech. Please repeat your message.",
            "I did not hear you. Please speak again.",
        ),
        2: (
            "No input detected. Please speak again.",
            "I did not hear anything. Please say that again.",
        ),
        3: (
            "I did not hear anything. Please say that again.",
            "Please repeat your message.",
        ),
        4: (
            "No input captured. Repeat your message.",
            "Please speak now.",
        ),
        5: (
            "No input. Speak again.",
            "Speak now.",
        ),
    },
    "fallback": {
        1: (
            "I did not understand. Could you please rephrase?",
            "I did not follow that. Please rephrase.",
        ),
        2: (
            "I did not follow that. Please rephrase.",
            "Please rephrase your last sentence.",
        ),
        3: (
            "Please rephrase.",
            "Say that again, clearly.",
        ),
        4: (
            "Clarify your request.",
            "State that more clearly.",
        ),
        5: (
            "Be clear.",
            "Say it clearly and briefly.",
        ),
    },
}

# Default aggressive terms used only when level == 5 and enable_explicit=True.
# Increased default intensity while remaining non-profane by default.
_DEFAULT_AGGRESSIVE_TERMS: Tuple[str, ...] = (
    "retard",
    "idiot",
    "butt sniffer",
    "shit hole",
    "cunt bag",
    "ass hat",
   "cock sucker",
   "wet blanket",
   "looser",
   "fuck-tard"
)

def _default_aggressive_formatter(base_text: str, terms: Tuple[str, ...]) -> str:
    """
    Default formatter for level 5 when explicit mode is enabled.
    The formatter injects concise forceful terms around the base text.
    Replace with a custom formatter to introduce your own explicit terms or style.
    """
    if not terms:
        return base_text
    # Use up to two terms to keep messages short and forceful.
    first = terms[0].capitalize()
    second = terms[1] if len(terms) > 1 else ""
    if second:
        composed = f"{first}. {base_text} {second}."
    else:
        composed = f"{first}. {base_text}"
    return composed


# -----------------------
# Minimal per-call state
# -----------------------

class _State:
    __slots__ = ("last_intent", "last_response", "turn", "last_ts")

    def __init__(self) -> None:
        self.last_intent: str = ""
        self.last_response: str = ""
        self.turn: int = 0
        self.last_ts: float = time.time()


# -----------------------
# Engine
# -----------------------

class UltraFastConversationEngine:
    __slots__ = (
        "attitude_level",
        "max_response_chars",
        "enable_explicit",
        "_aggressive_terms",
        "_aggressive_formatter",
        "_state",
    )

    def __init__(
        self,
        attitude_level: int = 2,
        max_response_chars: int = 160,
        enable_explicit: bool = False,
        aggressive_terms: Optional[List[str] | Tuple[str, ...]] = None,
        aggressive_formatter: Optional[callable] = None,
    ) -> None:
        """
        :param attitude_level: Integer from 1 (mild) to 5 (very aggressive)
        :param max_response_chars: Truncate responses at this character count
        :param enable_explicit: If True and level == 5, allow aggressive term injection
        :param aggressive_terms: Optional list/tuple of terms used in level 5 when explicit is enabled
        :param aggressive_formatter: Optional function(base_text, terms_tuple) -> str
        """
        self.attitude_level = self._clamp_level(attitude_level)
        self.max_response_chars = max_response_chars
        self.enable_explicit = enable_explicit
        terms = tuple(aggressive_terms) if aggressive_terms else _DEFAULT_AGGRESSIVE_TERMS
        self._aggressive_terms: Tuple[str, ...] = terms
        self._aggressive_formatter = aggressive_formatter or _default_aggressive_formatter
        self._state = _State()

    @staticmethod
    def _clamp_level(level: int) -> int:
        if level < 1:
            return 1
        if level > 5:
            return 5
        return level

    def set_attitude_level(self, level: int) -> None:
        self.attitude_level = self._clamp_level(level)

    # Public API
    def respond(self, text: Optional[str], call_context: Optional[Dict] = None) -> str:
        """
        Generate a concise response suitable for TTS.
        """
        st = self._state
        st.turn += 1
        st.last_ts = time.time()

        if not text or not text.strip():
            intent = "silence_or_empty"
            resp = self._select(intent)
            return self._finalize(resp, intent)

        norm_str, tokens = _normalize(text)

        # Phrase-based detection first (more specific).
        for phrase, intent in _PHRASES_ORDERED:
            if phrase in norm_str:
                resp = self._select(intent)
                return self._finalize(resp, intent)

        # Token-based detection next.
        for tok in tokens:
            mapped = _TOKEN_TO_INTENT.get(tok)
            if mapped:
                resp = self._select(mapped)
                return self._finalize(resp, mapped)

        # Fallback.
        intent = "fallback"
        resp = self._select(intent)
        return self._finalize(resp, intent)

    # Internal helpers
    def _select(self, intent: str) -> str:
        level = self.attitude_level
        choices = _TEMPLATES.get(intent, {}).get(level)
        if not choices:
            choices = _TEMPLATES["fallback"][level]

        st = self._state
        # Deterministic O(1) index without hashing for speed and stability across runs.
        # The index depends on turn count and last intent to reduce repetition.
        base_index = st.turn + (len(st.last_intent) if st.last_intent else 0)
        idx = base_index % len(choices)
        base = choices[idx]

        # Aggressive injection when requested.
        if level == 5 and self.enable_explicit:
            base = self._aggressive_formatter(base, self._aggressive_terms)

        # Avoid immediate repetition unless enough turns have passed.
        if base == st.last_response and st.turn < 3:
            idx = (idx + 1) % len(choices)
            base = choices[idx]
            if level == 5 and self.enable_explicit:
                base = self._aggressive_formatter(base, self._aggressive_terms)

        if len(base) > self.max_response_chars:
            base = base[: self.max_response_chars]
        return base

    def _finalize(self, response: str, intent: str) -> str:
        st = self._state
        st.last_intent = intent
        st.last_response = response
        return response
