/**
 * Listen audio helper
 * - Ensures the remote audio (caller) is attached for “listen now”.
 * - Works with generic WebRTC PeerConnection and is defensive for Twilio Voice SDK.
 * - Creates/uses a hidden <audio> element that autoplays with playsInline.
 * - No slang, production style.
 */

(function () {
  'use strict';

  // Ensure a single hidden audio element exists
  function ensureAudioElement() {
    const existing =
      document.getElementById('listen-audio') ||
      document.querySelector('[data-role="listen-audio"]');
    if (existing) {
      configureAudioElement(existing);
      return existing;
    }
    const el = document.createElement('audio');
    el.id = 'listen-audio';
    el.setAttribute('data-role', 'listen-audio');
    document.body.appendChild(el);
    configureAudioElement(el);
    return el;
  }

  function configureAudioElement(el) {
    el.autoplay = true;
    el.playsInline = true;
    el.controls = false;
    el.muted = false;
    el.style.position = 'fixed';
    el.style.width = '1px';
    el.style.height = '1px';
    el.style.opacity = '0';
    el.style.pointerEvents = 'none';
    el.style.zIndex = '0';
  }

  const listenAudioEl = ensureAudioElement();

  // Attach a MediaStream to the audio element
  function attachRemoteStream(stream) {
    if (!stream) return;
    try {
      listenAudioEl.srcObject = stream;
      const play = listenAudioEl.play();
      if (play && typeof play.catch === 'function') {
        play.catch(() => {
          // Autoplay may require a gesture; provide a safe fallback activator
          document.addEventListener(
            'click',
            function once() {
              listenAudioEl.play().catch(() => void 0);
              document.removeEventListener('click', once, true);
            },
            true
          );
        });
      }
    } catch {
      /* no-op */
    }
  }

  // Attach a single remote audio track
  function attachRemoteTrack(track) {
    if (!track || track.kind !== 'audio') return;
    const stream = new MediaStream([track]);
    attachRemoteStream(stream);
  }

  // Integrate with a generic RTCPeerConnection for “listen now”
  function attachPeerConnection(pc) {
    if (!pc) return;
    // Listen for remote tracks being added
    if (typeof pc.addEventListener === 'function') {
      pc.addEventListener('track', (evt) => {
        const [stream] = evt.streams || [];
        if (stream) attachRemoteStream(stream);
        else attachRemoteTrack(evt.track);
      });
    } else if (typeof pc.ontrack === 'object' || typeof pc.ontrack === 'function') {
      const original = pc.ontrack;
      pc.ontrack = function (evt) {
        const [stream] = evt.streams || [];
        if (stream) attachRemoteStream(stream);
        else attachRemoteTrack(evt.track);
        if (typeof original === 'function') original.call(pc, evt);
      };
    }
  }

  // Defensive Twilio Voice support (if present)
  function tryAttachTwilio() {
    const w = window;
    if (!w.Twilio || !w.Twilio.Device) return;

    // Twilio Voice v2 typically manages its own audio element; we defensively attach if possible.
    try {
      w.Twilio.Device.on('connect', (connection) => {
        // Some SDK versions expose mediaStream or getRemoteStream()
        const stream =
          (connection && connection.mediaStream) ||
          (connection && typeof connection.getRemoteStream === 'function'
            ? connection.getRemoteStream()
            : null);

        if (stream instanceof MediaStream) {
          attachRemoteStream(stream);
        }
      });

      // If there is an already active connection
      if (typeof w.Twilio.Device.activeConnection === 'function') {
        const active = w.Twilio.Device.activeConnection();
        if (active) {
          const stream =
            (active && active.mediaStream) ||
            (active && typeof active.getRemoteStream === 'function'
              ? active.getRemoteStream()
              : null);
          if (stream instanceof MediaStream) attachRemoteStream(stream);
        }
      }
    } catch {
      /* no-op */
    }
  }

  // Public API on window for your code to call explicitly
  window.ListenAudio = {
    attachRemoteStream,
    attachRemoteTrack,
    attachPeerConnection,
    element: listenAudioEl
  };

  // Attempt Twilio integration if present
  tryAttachTwilio();

  // Improve odds of autoplay succeeding on SPA route changes
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && listenAudioEl.srcObject) {
      const p = listenAudioEl.play();
      if (p && typeof p.catch === 'function') p.catch(() => void 0);
    }
  });

  // If any global scroll locks were left behind by route transitions, clean them up
  // (This complements the CSS so most pages regain scrolling without code changes.)
  const clearScrollLocks = () => {
    document.documentElement.classList.remove('no-scroll', 'modal-open');
    document.body.classList.remove('no-scroll', 'modal-open');
    document.documentElement.style.overflowY = '';
    document.body.style.overflowY = '';
  };

  window.addEventListener('pageshow', clearScrollLocks);
  window.addEventListener('hashchange', clearScrollLocks);
  window.addEventListener('popstate', clearScrollLocks);
})();
