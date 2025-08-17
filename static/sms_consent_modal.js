/* SMS Consent Modal for /scamtexts
   - Injects a "SMS consent info" button next to #btnSendNow
   - Opens a <dialog> explaining consent and provides a copyable message
   - Pulls the configured SMS From number from /api/texts/status
*/

(function () {
  "use strict";

  function qs(sel, root) { return (root || document).querySelector(sel); }
  function qsa(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }
  function escapeHtml(s) { return (s || "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[c])); }

  function showToast(msg) {
    try {
      // Use existing toast if present on the page
      if (typeof window.showToast === "function") return window.showToast(msg);
    } catch (e) {}
    // Fallback: unobtrusive alert-style toast
    console.log("[sms-consent]", msg);
  }

  function pickFromNumber(data) {
    if (!data || typeof data !== "object") return null;
    // Try common shapes
    const candidates = [
      data.from, data.from_number, data.sms_from, data.sms_from_number,
      data.SMS_FROM_NUMBER, data.SMS_FROM, data.fromSingle,
    ];
    for (const c of candidates) if (typeof c === "string" && c.trim()) return c.trim();

    // Pools
    const pools = [data.from_numbers, data.sms_from_numbers, data.pool, data.SMS_FROM_NUMBERS];
    for (const p of pools) {
      if (Array.isArray(p) && p.length) {
        const v = (p[0] || "").toString().trim();
        if (v) return v;
      }
      if (typeof p === "string" && p.includes(",")) {
        const first = p.split(",")[0].trim();
        if (first) return first;
      }
    }
    return null;
  }

  async function getSmsStatus() {
    try {
      const res = await fetch("/api/texts/status", { method: "GET", cache: "no-cache" });
      if (!res.ok) throw new Error("Failed to load SMS status.");
      return await res.json();
    } catch (err) {
      return {};
    }
  }

  function createDialog() {
    const dlg = document.createElement("dialog");
    dlg.id = "smsConsentDialog";
    dlg.setAttribute("aria-labelledby", "smscTitle");
    dlg.innerHTML = [
      '<div class="smsc-head">',
      '  <h2 id="smscTitle" class="smsc-title">SMS consent required</h2>',
      '  <button type="button" class="smsc-close" data-action="close" aria-label="Close">Close</button>',
      "</div>",
      '<div class="smsc-body">',
      '  <p class="smsc-note">',
      '    Due to legal and carrier requirements, automated SMS may only be sent to recipients who have provided prior consent.',
      '  </p>',
      '  <div class="smsc-box" id="smscFromBox">',
      '    <div class="smsc-inline">',
      '      <strong>SMS From:</strong>',
      '      <span id="smscFromNum" style="margin-left:8px;">(not configured)</span>',
      '    </div>',
      '    <div class="smsc-small" id="smscFromHint" style="margin-top:6px;"></div>',
      '  </div>',
      '  <ol class="smsc-steps">',
      '    <li>Share the instructions below with your contact.</li>',
      '    <li>The contact must opt in by sending <span class="smsc-kbd">START</span> to the number above.</li>',
      '    <li>They can send <span class="smsc-kbd">STOP</span> at any time to opt out, and <span class="smsc-kbd">HELP</span> for information.</li>',
      '  </ol>',
      '  <div class="smsc-box">',
      '    <label for="smscTemplate" class="smsc-small">Instructions to share</label>',
      '    <textarea id="smscTemplate" class="smsc-monotext" readonly></textarea>',
      '    <div class="smsc-row" style="margin-top:10px;">',
      '      <button type="button" class="smsc-btn primary" data-action="copy">Copy instructions</button>',
      '      <a class="smsc-btn" id="smscSmsLink" href="#" target="_blank" rel="noopener">Open messaging app</a>',
      '    </div>',
      '  </div>',
      '  <p class="smsc-small">',
      '    Note: Consent cannot be granted programmatically. The recipient must opt in (e.g., by sending <span class="smsc-kbd">START</span>).',
      '  </p>',
      '</div>',
      '<div class="smsc-footer">',
      '  <span class="smsc-small">After consent is confirmed, you can use “Send now”.</span>',
      '  <div class="smsc-row">',
      '    <a class="smsc-link smsc-small" href="/admin" title="Open SMS settings">SMS settings</a>',
      '    <button type="button" class="smsc-btn" data-action="close">Close</button>',
      '  </div>',
      '</div>'
    ].join("");
    document.body.appendChild(dlg);
    return dlg;
  }

  function setTemplate(dlg, fromNum) {
    const t = qs("#smscTemplate", dlg);
    const num = fromNum || "(configure SMS From number)";
    const company = document.body.getAttribute("data-company-name") || "this service";
    const msg = [
      `I would like to send you a few automated text messages from ${company}.`,
      `To consent, please text START to ${num}.`,
      `You can text STOP anytime to opt out, and HELP for information.`
    ].join(" ");
    t.value = msg;

    const link = qs("#smscSmsLink", dlg);
    if (fromNum && fromNum.startsWith("+")) {
      // sms: link with a prefilled body compatible with most devices
      const body = encodeURIComponent("START");
      link.href = `sms:${encodeURIComponent(fromNum)}?&body=${body}`;
    } else {
      link.href = "#";
    }
  }

  async function openDialog(dlg) {
    // Populate runtime data
    const status = await getSmsStatus();
    let fromNum = pickFromNumber(status);

    const fromNumEl = qs("#smscFromNum", dlg);
    const fromHintEl = qs("#smscFromHint", dlg);
    if (fromNum) {
      fromNumEl.textContent = fromNum;
      fromHintEl.textContent = "";
    } else {
      fromNumEl.textContent = "(not configured)";
      fromHintEl.innerHTML = 'Set SMS_FROM_NUMBER (or a pool) in <a href="/admin" class="smsc-link">Admin</a>.';
    }
    setTemplate(dlg, fromNum);

    // Open the dialog
    if (typeof dlg.showModal === "function") dlg.showModal();
    else dlg.setAttribute("open", "true");
  }

  function wireDialog(dlg) {
    dlg.addEventListener("click", (ev) => {
      const t = ev.target;
      if (!(t instanceof HTMLElement)) return;
      const action = t.getAttribute("data-action");
      if (action === "close") {
        if (typeof dlg.close === "function") dlg.close();
        else dlg.removeAttribute("open");
      }
      if (action === "copy") {
        const ta = qs("#smscTemplate", dlg);
        if (ta) {
          ta.select();
          try {
            const txt = ta.value;
            if (navigator.clipboard && navigator.clipboard.writeText) {
              navigator.clipboard.writeText(txt).then(
                () => showToast("Instructions copied to clipboard."),
                () => document.execCommand("copy")
              );
            } else {
              document.execCommand("copy");
            }
          } catch (e) {
            showToast("Copy failed.");
          }
        }
      }
    });
  }

  function injectButton(dlg) {
    // Try to place the button near the "Send now" button on /scamtexts
    const sendBtn = qs("#btnSendNow") || qs("[data-action='send-now']");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.id = "btnSmsConsentInfo";
    btn.className = "smsc-btn"; // Minimal style; blends with dialog theme
    btn.textContent = "SMS consent info";

    btn.addEventListener("click", () => openDialog(dlg));

    // Insert next to the send button, otherwise append to body top
    if (sendBtn && sendBtn.parentElement) {
      // Place just after the send button
      sendBtn.parentElement.insertBefore(btn, sendBtn.nextSibling);
      // Add a little spacing
      btn.style.marginLeft = "8px";
    } else {
      document.body.insertBefore(btn, document.body.firstChild);
      btn.style.position = "fixed";
      btn.style.right = "16px";
      btn.style.top = "16px";
      btn.style.zIndex = "2000";
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    // Only activate on /scamtexts
    if (!location.pathname || !/\/scamtexts\/?$/.test(location.pathname)) return;

    const dlg = createDialog();
    wireDialog(dlg);
    injectButton(dlg);
  });
})();
