(function () {
  "use strict";

  // DOM helpers
  const qs = (sel, ctx = document) => ctx.querySelector(sel);
  const qsa = (sel, ctx = document) => Array.from(ctx.querySelectorAll(sel));

  // Toast helper
  function showToast(message, durationMs = 3200) {
    const el = qs("#toast");
    if (!el) return;
    el.textContent = message;
    el.classList.add("toast--show");
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => {
      el.classList.remove("toast--show");
    }, durationMs);
  }

  // Escaping for safe HTML insertion
  function escapeHtml(s) {
    return (s || "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
    }[c]));
  }

  // Format seconds to mm:ss
  function formatMMSS(totalSeconds) {
    const s = Math.max(0, Math.floor(totalSeconds || 0));
    const m = Math.floor(s / 60);
    const r = s % 60;
    return `${String(m).padStart(2, "0")}:${String(r).padStart(2, "0")}`;
  }

  // Build a large visual countdown ring as an SVG
  function buildCountdownBadge(remainSec, totalSec, paused = false) {
    const size = 168; // px
    const stroke = 10;
    const r = (size - stroke) / 2;
    const c = 2 * Math.PI * r;

    let pct = 0;
    if (totalSec && totalSec > 0) {
      const elapsed = Math.max(0, totalSec - Math.max(0, remainSec));
      pct = Math.max(0, Math.min(1, elapsed / totalSec));
    }
    const dash = `${(c * pct).toFixed(2)} ${c.toFixed(2)}`;
    const ringColor = paused ? "#8892a6" : "var(--accent, #25c2a0)";

    return `
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" aria-hidden="true" style="display:block">
        <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="rgba(255,255,255,0.12)" stroke-width="${stroke}" />
        <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${ringColor}" stroke-width="${stroke}"
                stroke-linecap="round" stroke-dasharray="${dash}" transform="rotate(-90 ${size / 2} ${size / 2})" />
      </svg>`;
  }

  async function safeErrorText(res) {
    try {
      return await res.text();
    } catch {
      return "";
    }
  }

  // -----------------------
  // Greeting modal logic
  // -----------------------
  const greetingModal = {
    el: null,
    input: null,
    wordCountEl: null,
    saveBtn: null,
    open() {
      if (!this.el) return;
      this.el.setAttribute("aria-hidden", "false");
      this.input.focus();
      this.updateWordCount();
    },
    close() {
      if (!this.el) return;
      this.el.setAttribute("aria-hidden", "true");
      this.input.value = "";
      this.updateWordCount();
    },
    getWordCount() {
      const text = (this.input.value || "").trim();
      if (!text) return 0;
      return text.split(/\s+/).filter(Boolean).length;
    },
    updateWordCount() {
      const n = this.getWordCount();
      if (this.wordCountEl) this.wordCountEl.textContent = `${n} words`;
      if (this.saveBtn) this.saveBtn.disabled = n < 5 || n > 15;
    },
  };

  function initGreetingModal() {
    const modal = qs("#greetingModal");
    if (!modal) return;

    greetingModal.el = modal;
    greetingModal.input = qs("#greetingInput", modal);
    greetingModal.wordCountEl = qs("#greetingWordCount", modal);
    greetingModal.saveBtn = qs("#greetingSaveBtn", modal);

    const openBtn = qs("#btnAddGreeting");
    const closeBtn = qs("#greetingCloseBtn");
    const cancelBtn = qs("#greetingCancelBtn");
    const saveBtn = qs("#greetingSaveBtn");

    if (greetingModal.input) {
      greetingModal.input.addEventListener("input", () => greetingModal.updateWordCount());
    }
    if (openBtn) openBtn.addEventListener("click", () => greetingModal.open());
    if (closeBtn) closeBtn.addEventListener("click", () => greetingModal.close());
    if (cancelBtn) cancelBtn.addEventListener("click", () => greetingModal.close());

    if (saveBtn) {
      saveBtn.addEventListener("click", async () => {
        const phrase = (greetingModal.input.value || "").trim();
        const words = phrase.split(/\s+/).filter(Boolean);
        if (words.length < 5 || words.length > 15) {
          showToast("Enter 5 to 15 words.");
          return;
        }
        saveBtn.disabled = true;
        try {
          const res = await fetch("/api/next-greeting", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ phrase }),
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok || (data && data.ok === false)) {
            const msg = (data && data.message) || (await safeErrorText(res));
            showToast(msg || "Failed to save greeting phrase.");
            return;
          }
          showToast("Greeting phrase queued for the next call.");
          greetingModal.close();
        } catch (err) {
          showToast((err && err.message) || "Failed to save greeting phrase.");
        } finally {
          saveBtn.disabled = false;
        }
      });
    }
  }

  // -----------------------
  // Call-now button wiring
  // -----------------------
  function initCallNow() {
    const btn = qs("#btnCallNow");
    if (!btn) return;
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        const res = await fetch("/api/call-now", { method: "POST" });
        const data = await res.json().catch(() => ({}));

        if (res.status === 429 || (data && data.ok === false && data.reason === "cap_reached")) {
          showToast("Maximum call attempts reached for the allotted time.");
        } else if (!res.ok || (data && data.ok === false)) {
          const msg = (data && data.message) || await safeErrorText(res);
          showToast(msg || "Call request failed.");
        } else {
          showToast("Call attempt requested.");
        }
      } catch (err) {
        showToast((err && err.message) || "Call request failed.");
      } finally {
        btn.disabled = false;
      }
    });
  }

  // -----------------------
  // Admin environment editor (matches /api/admin/env contract)
  // -----------------------
  async function loadEnvEditor() {
    const container = qs("#envEditor");
    const isAdmin = document.body.getAttribute("data-is-admin") === "1";
    if (!container || !isAdmin) return;

    const endpoint = container.getAttribute("data-endpoint-get") || "/api/admin/env";
    container.setAttribute("aria-busy", "true");
    try {
      const res = await fetch(endpoint, { method: "GET", cache: "no-cache" });
      if (!res.ok) throw new Error((await res.text()) || "Failed to load settings.");
      const data = await res.json();
      renderEnvTable(data.editable || []);
    } catch (err) {
      container.innerHTML = `<div class="alert">Error: ${escapeHtml(err.message || "Failed to load settings.")}</div>`;
    } finally {
      container.removeAttribute("aria-busy");
    }
  }

  function renderEnvTable(items) {
    const container = qs("#envEditor");
    if (!container) return;
    container.innerHTML = "";

    const table = document.createElement("table");
    table.className = "env-table";
    const thead = document.createElement("thead");
    thead.innerHTML = "<tr><th style='width:28%'>Key</th><th>Value</th></tr>";
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    items.forEach((row) => {
      const tr = document.createElement("tr");
      const tdKey = document.createElement("td");
      const tdVal = document.createElement("td");

      const keyLabel = document.createElement("div");
      keyLabel.textContent = row.key;
      keyLabel.style.fontFamily = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace";
      keyLabel.style.fontSize = "0.95rem";
      tdKey.appendChild(keyLabel);

      let input;
      if (row.key.endsWith("_DAYS")) {
        input = document.createElement("input");
        input.type = "text";
        input.placeholder = "Mon,Tue,Wed,Thu,Fri";
        input.value = row.value ?? "";
      } else if (row.key.endsWith("_HOURS_LOCAL")) {
        input = document.createElement("input");
        input.type = "text";
        input.placeholder = "09:00-18:00";
        input.value = row.value ?? "";
      } else if (row.key.endsWith("_SECONDS")) {
        input = document.createElement("input");
        input.type = "number";
        input.step = "1";
        input.min = "0";
        input.value = String(row.value ?? "");
      } else if (["ROTATE_PROMPTS", "USE_NGROK", "NONINTERACTIVE", "LOG_COLOR", "ENABLE_MEDIA_STREAMS"].includes(row.key)) {
        input = document.createElement("select");
        ["true", "false"].forEach((v) => {
          const opt = document.createElement("option");
          opt.value = v;
          opt.textContent = v;
          if ((row.value ?? "").toString().toLowerCase() === v) opt.selected = true;
          input.appendChild(opt);
        });
      } else {
        input = document.createElement("input");
        input.type = "text";
        input.value = row.value ?? "";
      }
      input.dataset.key = row.key;
      input.autocomplete = "off";

      tdVal.appendChild(input);
      tr.appendChild(tdKey);
      tr.appendChild(tdVal);
      tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    container.appendChild(table);

    const saveBtn = qs("#btnSaveEnv");
    if (saveBtn) saveBtn.disabled = false;
  }

  async function saveEnvEditor() {
    const container = qs("#envEditor");
    if (!container) return;
    const endpoint = container.getAttribute("data-endpoint-post") || "/api/admin/env";

    const inputs = qsa("input, select, textarea", container);
    const updates = {};
    inputs.forEach((el) => {
      const key = el.dataset.key;
      if (!key) return;
      updates[key] = el.value;
    });

    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ updates }),
      });
      if (!res.ok) throw new Error((await res.text()) || "Failed to save settings.");
      showToast("Settings saved.");
    } catch (err) {
      showToast((err && err.message) || "Failed to save settings.");
    }
  }

  function initAdminPanel() {
    const isAdmin = document.body.getAttribute("data-is-admin") === "1";
    if (!isAdmin) return;
    loadEnvEditor();
    qs("#btnSaveEnv")?.addEventListener("click", saveEnvEditor);
  }

  // -----------------------
  // Status poller and UI (countdown + labels)
  // -----------------------
  let statusTimer = null;
  let callActive = false; // Tracks in-progress state when provided by backend

  function renderNumbersLine(data) {
    const to = data.to_number || "";
    const fromSingle = data.from_number || "";
    const fromPool = Array.isArray(data.from_numbers) ? data.from_numbers : [];

    let fromText = "";
    if (fromPool && fromPool.length > 0) {
      const example = fromPool[0] || "";
      const extra = Math.max(0, fromPool.length - 1);
      fromText = extra > 0 ? `${example} (+${extra} more)` : example;
    } else if (fromSingle) {
      fromText = fromSingle;
    } else {
      fromText = "Not configured";
    }

    const toText = to || "Not configured";
    return `<div class="muted" style="font-size:.9rem; margin-top:.5rem; color:var(--muted,#aab2bd);">
      To: <span style="opacity:.8; font-variant-numeric: tabular-nums;">${escapeHtml(toText)}</span>
      &nbsp;&nbsp; From: <span style="opacity:.8; font-variant-numeric: tabular-nums;">${escapeHtml(fromText)}</span>
    </div>`;
  }

  function renderStatus(data) {
    const area = qs("#statusArea");
    if (!area) return;

    // Track active call if backend reports it
    if (typeof data.call_in_progress === "boolean") {
      callActive = data.call_in_progress;
    }

    const parts = [];

    // Show last placement error if recent (within 10 minutes)
    const err = data.last_error;
    if (err && err.message) {
      const age = Date.now() / 1000 - (err.ts || 0);
      if (age < 600) {
        parts.push(`<div class="alert">Last error: ${escapeHtml(err.message)}</div>`);
      }
    }

    // Active window chip
    if (data.within_active_window) {
      parts.push(`<div class="chip" style="display:inline-flex;align-items:center;gap:.5rem;padding:.35rem .6rem;border:1px solid var(--border);border-radius:999px;background:rgba(0,0,0,.2);">
        <span style="width:.55rem;height:.55rem;border-radius:50%;background:var(--accent,#25c2a0);display:inline-block"></span>
        <span>${data.call_in_progress ? "Active call in progress" : "Active window"}</span>
      </div>`);
    } else {
      parts.push(`<div class="chip" style="display:inline-flex;align-items:center;gap:.5rem;padding:.35rem .6rem;border:1px solid var(--border);border-radius:999px;background:rgba(0,0,0,.2);">
        <span style="width:.55rem;height:.55rem;border-radius:50%;background:#e55353;display:inline-block"></span>
        <span>Inactive now (hours ${escapeHtml(data.active_hours_local || "")})</span>
      </div>`);
    }

    // Attempts summary
    parts.push(
      `<span class="muted" style="margin-left:.6rem">Attempts (1h/day): ${data.attempts_last_hour}/${data.hourly_max_attempts} · ${data.attempts_last_day}/${data.daily_max_attempts}</span>`
    );

    // Countdown logic
    let remain = 0;
    let total = 0;
    if (!data.can_attempt_now && data.wait_seconds_if_capped > 0) {
      remain = data.wait_seconds_if_capped;
      total = data.wait_seconds_if_capped;
    } else if (typeof data.seconds_until_next === "number" && data.seconds_until_next != null) {
      remain = data.seconds_until_next;
      total = (typeof data.interval_total_seconds === "number" && data.interval_total_seconds > 0)
        ? data.interval_total_seconds
        : (data.seconds_until_next || 0);
    }

    const paused = !data.within_active_window || !!callActive;
    const svg = buildCountdownBadge(remain, total, paused);

    let label = "";
    if (callActive) {
      label = "Calling now";
    } else if (!data.within_active_window) {
      label = "Waiting for active window";
    } else if (!data.can_attempt_now && data.wait_seconds_if_capped > 0) {
      label = "Waiting due to attempt cap";
    } else if (typeof remain === "number") {
      label = "Next attempt";
    }

    const labelBlock =
      `<div style="display:flex;flex-direction:column;justify-content:center">
        <div style="font-size:1.05rem; line-height:1; font-weight:600; color:var(--text,#f3f5f7);">${escapeHtml(label)}</div>
        <div style="font-size:1.6rem; line-height:1.2; font-variant-numeric: tabular-nums; color:var(--muted,#aab2bd);">in ${formatMMSS(remain)}</div>
        ${renderNumbersLine(data)}
      </div>`;

    const focal =
      `<div style="display:flex;align-items:center;gap:1rem;margin-top:.9rem">
        <div style="flex:0 0 auto">${svg}</div>
        <div style="flex:1 1 auto">${labelBlock}</div>
      </div>`;

    area.innerHTML = `${parts.join(" ")} ${focal}`;
  }

  async function pollStatusOnce() {
    try {
      const res = await fetch("/api/status", { method: "GET", cache: "no-cache" });
      if (!res.ok) throw new Error(await safeErrorText(res) || "Failed to load status.");
      const data = await res.json();

      if (typeof data.call_in_progress === "boolean" && callActive !== true) {
        callActive = data.call_in_progress;
      }
      renderStatus(data);
    } catch {
      const area = qs("#statusArea");
      if (area) {
        area.innerHTML = `<div class="muted">Status unavailable.</div>`;
      }
    }
  }

  function initStatusPoll() {
    pollStatusOnce();
    clearInterval(statusTimer);
    statusTimer = setInterval(pollStatusOnce, 1000);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) pollStatusOnce();
    });
  }

  // -----------------------
  // Live conversation UI (transcript + optional audio listen)
  // -----------------------
  // Style for live panel visuals
  (function ensureLivePanelStyle() {
    const id = "live-convo-style";
    if (qs(`#${id}`)) return;
    const style = document.createElement("style");
    style.id = id;
    style.textContent = `
      #livePanel .conversation {
        transition: background-color .25s ease, box-shadow .25s ease, border-color .25s ease;
      }
      #livePanel.active .conversation {
        background-color: rgba(0,0,0,0.78);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 12px 14px;
        box-shadow: inset 0 0 0 1px rgba(255,255,255,0.02), 0 10px 30px rgba(0,0,0,0.35);
      }
      #livePanel .conv-line {
        margin: .25rem 0;
        line-height: 1.35;
      }
      #livePanel .conv-role {
        font-weight: 600;
        margin-right: .4rem;
      }
      #livePanel .conv-role.assistant { color: #7ec8ff; }
      #livePanel .conv-role.callee { color: #ffd27e; }
      #listenStatus { min-width: 9ch; text-align: right; }
    `;
    document.head.appendChild(style);
  })();

  let liveTimer = null;
  let ws = null;
  let audioCtx = null;
  let scriptNode = null;
  let audioQueue = [];
  let playing = false;

  function ensureLivePanel() {
    let panel = qs("#livePanel");
    if (panel) return panel;
    const main = qs("main") || document.body;
    panel = document.createElement("section");
    panel.id = "livePanel";
    panel.className = "panel";
    panel.innerHTML = `
      <div class="panel-header" style="display:flex;justify-content:space-between;align-items:center;gap:1rem">
        <h2 class="panel-title">Live Conversation</h2>
        <div style="display:flex;align-items:center;gap:.5rem">
          <button id="btnListenLive" class="btn" disabled>Listen live</button>
          <span id="listenStatus" class="muted" aria-live="polite"></span>
        </div>
      </div>
      <div id="liveConversation" class="conversation" style="min-height:140px"></div>
    `;
    main.appendChild(panel);
    return panel;
  }

  function appendTranscriptEntry(container, entry) {
    const role = entry.role || "Speaker";
    const text = entry.text || "";
    const line = document.createElement("div");
    line.className = "conv-line";
    line.setAttribute("data-role", role);
    line.setAttribute("data-final", entry.final ? "1" : "0");
    line.innerHTML = `<span class="conv-role ${role === "Assistant" ? "assistant" : "callee"}">${escapeHtml(role)}:</span> <span class="conv-text">${escapeHtml(text)}</span>`;
    container.appendChild(line);
    container.scrollTop = container.scrollHeight;
  }

  // Merge logic: render finals and keep only one updating partial callee line
  function renderLiveTranscriptList(container, list) {
    const finals = list.filter((e) => e && e.final);
    const latestPartial = [...list].reverse().find((e) => e && !e.final);

    const prevFinalCount = Number(container.getAttribute("data-final-count") || "0");
    if (finals.length !== prevFinalCount) {
      container.innerHTML = "";
      finals.forEach((e) => appendTranscriptEntry(container, e));
      container.setAttribute("data-final-count", String(finals.length));
    }
    let partialEl = qs(".conv-line[data-final='0']", container);
    if (latestPartial && latestPartial.text) {
      if (!partialEl) {
        partialEl = document.createElement("div");
        partialEl.className = "conv-line";
        partialEl.setAttribute("data-final", "0");
        partialEl.innerHTML = `<span class="conv-role callee">Callee:</span> <span class="conv-text"></span>`;
        container.appendChild(partialEl);
      }
      qs(".conv-text", partialEl).textContent = latestPartial.text;
      container.scrollTop = container.scrollHeight;
    } else {
      if (partialEl) partialEl.remove();
    }
  }

  async function pollLiveTranscript() {
    try {
      const res = await fetch("/api/live", { method: "GET", cache: "no-cache" });
      if (!res.ok) return;
      const data = await res.json();
      const container = qs("#liveConversation");
      const btn = qs("#btnListenLive");
      const status = qs("#listenStatus");
      const panel = qs("#livePanel");
      if (!container || !btn || !status || !panel) return;

      const inProgress = !!data.in_progress;
      callActive = inProgress;
      panel.classList.toggle("active", inProgress);

      // Enable/disable Listen button based on feature flag and call state
      btn.disabled = !inProgress || !data.media_streams_enabled;

      // Render merged transcript
      const list = Array.isArray(data.transcript) ? data.transcript : [];
      renderLiveTranscriptList(container, list);

      // Stop listening automatically when call ends
      if (!inProgress && ws) {
        stopListening();
      }
    } catch {
      // ignore transient errors
    }
  }

  function initLivePanel() {
    const panel = ensureLivePanel();
    const btn = qs("#btnListenLive", panel);
    btn?.addEventListener("click", () => {
      if (ws) stopListening();
      else startListening();
    });
    clearInterval(liveTimer);
    liveTimer = setInterval(pollLiveTranscript, 1000);
    pollLiveTranscript();
  }

  // Audio handling with μ-law 8 kHz -> AudioContext sample-rate conversion
  function mulawDecodeSample(mu) {
    mu = ~mu & 0xff;
    const sign = (mu & 0x80) ? -1 : 1;
    const exponent = (mu >> 4) & 0x07;
    const mantissa = mu & 0x0f;
    let sample = ((mantissa << 4) + 8) << (exponent + 3);
    sample = sign * (sample - 33);
    return Math.max(-1, Math.min(1, sample / 32768));
  }

  function decodeMuLawToFloat32(payloadB64) {
    const bin = atob(payloadB64);
    const out = new Float32Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = mulawDecodeSample(bin.charCodeAt(i));
    }
    return out; // 8 kHz mono
  }

  function resampleToContextRate(src8k, contextRate) {
    if (!src8k || src8k.length === 0) return src8k;
    const srcRate = 8000;
    if (contextRate === srcRate) return src8k;
    const ratio = contextRate / srcRate;
    const outLen = Math.max(1, Math.floor(src8k.length * ratio));
    const out = new Float32Array(outLen);
    for (let i = 0; i < outLen; i++) {
      const srcPos = i / ratio;
      const i0 = Math.floor(srcPos);
      const i1 = Math.min(src8k.length - 1, i0 + 1);
      const frac = srcPos - i0;
      out[i] = src8k[i0] * (1 - frac) + src8k[i1] * frac;
    }
    return out;
  }

  function audioProcess(ev) {
    const out = ev.outputBuffer.getChannelData(0);
    out.fill(0);
    if (!playing || audioQueue.length === 0) return;
    const chunk = audioQueue.shift();
    if (!chunk) return;
    const n = Math.min(out.length, chunk.length);
    out.set(chunk.subarray(0, n), 0);
    if (chunk.length > n) {
      audioQueue.unshift(chunk.subarray(n));
    }
  }

  function startListening() {
    const status = qs("#listenStatus");
    const btn = qs("#btnListenLive");

    if (btn && btn.disabled) return;

    try {
      const scheme = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${scheme}://${location.host}/client-audio`);
      ws.onopen = async () => {
        if (!audioCtx) {
          audioCtx = new (window.AudioContext || window.webkitAudioContext)();
          try { await audioCtx.resume(); } catch {}
          scriptNode = audioCtx.createScriptProcessor(4096, 0, 1);
          scriptNode.onaudioprocess = audioProcess;
          scriptNode.connect(audioCtx.destination);
        }
        playing = true;
        if (status) status.textContent = "Connected";
        if (btn) btn.textContent = "Stop listening";
      };
      ws.onmessage = (ev) => {
        const payloadB64 = ev.data;
        const pcm8k = decodeMuLawToFloat32(payloadB64);
        const pcm = resampleToContextRate(pcm8k, audioCtx ? audioCtx.sampleRate : 8000);
        audioQueue.push(pcm);
      };
      ws.onclose = () => {
        playing = false;
        if (status) status.textContent = "Disconnected";
        if (btn) btn.textContent = "Listen live";
        ws = null;
      };
      ws.onerror = () => {
        playing = false;
        if (status) status.textContent = "Audio error";
        if (btn) btn.textContent = "Listen live";
        try { ws && ws.close(); } catch {}
        ws = null;
      };
    } catch {
      if (status) status.textContent = "Audio not available";
      if (btn) btn.textContent = "Listen live";
      ws = null;
    }
  }

  function stopListening() {
    const btn = qs("#btnListenLive");
    const status = qs("#listenStatus");
    try { ws && ws.close(); } catch {}
    ws = null;
    playing = false;
    if (status) status.textContent = "Stopped";
    if (btn) btn.textContent = "Listen live";
  }

  document.addEventListener("visibilitychange", () => {
    if (document.hidden && ws) stopListening();
  });

  // -----------------------
  // Init
  // -----------------------
  document.addEventListener("DOMContentLoaded", () => {
    initGreetingModal();
    initCallNow();
    initAdminPanel();
    initStatusPoll();
    initLivePanel();
  });
})();
