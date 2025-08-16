(function () {
  "use strict";

  const qs = (s, c = document) => c.querySelector(s);
  const qsa = (s, c = document) => Array.from(c.querySelectorAll(s));

  function maskNumber(num) {
    if (!num) return "";
    const s = String(num);
    const digits = s.replace(/[^\d+]/g, "");
    if (digits.length <= 4) return "****";
    return "****" + digits.slice(-4);
  }

  function htmlEscape(s) {
    return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function renderStatusBox(data) {
    const el = qs("#statusArea");
    if (!el) return;
    const lines = [];
    lines.push(`<div class="kv"><div class="k">Enabled</div><div class="v">${data.sms_enabled ? "Yes" : "No"}</div></div>`);
    lines.push(`<div class="kv"><div class="k">Within active window</div><div class="v">${data.within_active_window ? "Yes" : "No"}</div></div>`);
    lines.push(`<div class="kv"><div class="k">Next send</div><div class="v">${data.seconds_until_next != null ? (data.seconds_until_next + "s") : "-"}</div></div>`);
    lines.push(`<div class="kv"><div class="k">Interval</div><div class="v">${data.interval_total_seconds != null ? (data.interval_total_seconds + "s") : "-"}</div></div>`);
    lines.push(`<div class="kv"><div class="k">Caps (hour/day)</div><div class="v">${data.hourly_max_attempts}/${data.daily_max_attempts}</div></div>`);
    lines.push(`<div class="kv"><div class="k">Attempts (last hour/day)</div><div class="v">${data.attempts_last_hour}/${data.attempts_last_day}</div></div>`);
    lines.push(`<div class="kv"><div class="k">To</div><div class="v">${maskNumber(data.to_number)}</div></div>`);
    const pool = (Array.isArray(data.from_numbers) ? data.from_numbers : []).filter(Boolean);
    lines.push(`<div class="kv"><div class="k">From</div><div class="v">${maskNumber(data.from_number)}${pool.length ? (" + " + pool.length + " pool") : ""}</div></div>`);
    if (data.template_preview) {
      lines.push(`<div class="kv"><div class="k">Template preview</div><div class="v">${htmlEscape(data.template_preview)}</div></div>`);
    }
    el.innerHTML = `
      <div class="card">
        <div class="kvgrid">
          ${lines.join("")}
        </div>
      </div>
    `;
  }

  function renderMetricsBox(m) {
    const el = qs("#metricsArea");
    if (!el) return;
    el.innerHTML = `
      <div class="stats-panel">
        <div class="stats-title">SMS Impact</div>
        <div class="stats-row"><div class="stats-label">Messages total</div><div class="stats-value">${m.total_messages || 0}</div></div>
        <div class="stats-row"><div class="stats-label">Delivered</div><div class="stats-value">${m.delivered_messages || 0}</div></div>
        <div class="stats-row"><div class="stats-label">Failed</div><div class="stats-value">${m.failed_messages || 0}</div></div>
      </div>
    `;
  }

  async function refreshStatus() {
    try {
      const r = await fetch("/api/texts/status");
      if (!r.ok) return;
      const d = await r.json();
      renderStatusBox(d);
    } catch {}
  }

  async function refreshMetrics() {
    try {
      const r = await fetch("/api/texts/metrics");
      if (!r.ok) return;
      const d = await r.json();
      renderMetricsBox(d);
    } catch {}
  }

  async function sendNow() {
    const btn = qs("#btnSendNow");
    if (btn) btn.disabled = true;
    try {
      const r = await fetch("/api/texts/send-now", { method: "POST" });
      const d = await r.json().catch(() => ({}));
      if (!r.ok || !d.ok) {
        alert("Failed to send: " + (d.error || d.reason || r.statusText));
      }
    } catch {
      alert("Failed to send.");
    } finally {
      if (btn) btn.disabled = false;
      refreshStatus();
      refreshMetrics();
    }
  }

  function openOpeningModal() {
    const m = qs("#openingModal");
    if (m) m.setAttribute("aria-hidden", "false");
    const t = qs("#openingInput");
    if (t) t.value = "";
    const e = qs("#openingError");
    if (e) e.textContent = "";
  }
  function closeOpeningModal() {
    const m = qs("#openingModal");
    if (m) m.setAttribute("aria-hidden", "true");
  }
  async function saveOpening() {
    const input = qs("#openingInput");
    const err = qs("#openingError");
    if (!input) return;
    const text = String(input.value || "").trim();
    if (!text) {
      if (err) err.textContent = "Enter a line.";
      return;
    }
    try {
      const r = await fetch("/api/texts/next-opening", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      const d = await r.json().catch(() => ({}));
      if (!d.ok) {
        if (err) err.textContent = d.error || "Failed to save.";
        return;
      }
      closeOpeningModal();
    } catch {
      if (err) err.textContent = "Failed to save.";
    }
  }

  // Admin ENV editor (simple)
  async function loadEnvEditor() {
    const container = qs("#envEditor");
    if (!container) return;
    try {
      const r = await fetch("/api/admin/env");
      if (r.status === 401) {
        container.innerHTML = `<div class="muted">Administrator login required to edit settings.</div>`;
        return;
      }
      if (!r.ok) {
        container.innerHTML = `<div class="muted">Failed to load settings.</div>`;
        return;
      }
      const d = await r.json();
      const rows = Array.isArray(d.editable) ? d.editable : [];
      const html = [];
      html.push(`<table class="env-table"><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>`);
      for (const item of rows) {
        const k = item.key || "";
        const v = item.value || "";
        html.push(`
          <tr>
            <td><code class="env-key">${htmlEscape(k)}</code></td>
            <td><input class="env-input" type="text" name="${htmlEscape(k)}" value="${htmlEscape(v)}" /></td>
          </tr>
        `);
      }
      html.push(`</tbody></table>`);
      container.innerHTML = html.join("");
    } catch {
      container.innerHTML = `<div class="muted">Failed to load settings.</div>`;
    }
  }

  async function saveEnvEditor() {
    const container = qs("#envEditor");
    if (!container) return;
    const msg = qs("#envSaveMsg");
    const inputs = qsa(".env-input", container);
    const updates = {};
    for (const inp of inputs) {
      const k = inp.name;
      const v = inp.value;
      updates[k] = v;
    }
    try {
      const r = await fetch("/api/admin/env", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ updates }),
      });
      const d = await r.json().catch(() => ({}));
      if (msg) msg.textContent = d.ok ? "Saved." : "Error saving.";
    } catch {
      if (msg) msg.textContent = "Error saving.";
    } finally {
      setTimeout(() => { if (msg) msg.textContent = ""; }, 2500);
    }
  }

  function bind() {
    const btnSend = qs("#btnSendNow");
    if (btnSend) btnSend.addEventListener("click", sendNow);

    const btnAdd = qs("#btnAddOpening");
    if (btnAdd) btnAdd.addEventListener("click", openOpeningModal);

    const btnSaveOpen = qs("#btnOpeningSave");
    if (btnSaveOpen) btnSaveOpen.addEventListener("click", saveOpening);

    const btnCancelOpen = qs("#btnOpeningCancel");
    if (btnCancelOpen) btnCancelOpen.addEventListener("click", closeOpeningModal);

    const btnSaveEnv = qs("#btnSaveEnv");
    if (btnSaveEnv) btnSaveEnv.addEventListener("click", saveEnvEditor);
  }

  document.addEventListener("DOMContentLoaded", () => {
    bind();
    loadEnvEditor();
    refreshStatus();
    refreshMetrics();
    setInterval(refreshStatus, 3000);
    setInterval(refreshMetrics, 6000);
  });
})();
