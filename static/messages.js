(function () {
  "use strict";

  const qs = (s, c = document) => c.querySelector(s);
  const qsa = (s, c = document) => Array.from(c.querySelectorAll(s));

  function showToast(msg, ms = 2800) {
    const el = qs("#toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.add("toast--show");
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => el.classList.remove("toast--show"), ms);
  }

  function buildGrid(values) {
    const grid = qs("#messagesGrid");
    grid.innerHTML = "";
    const N = 10;
    const vals = values.slice(0, N);
    while (vals.length < N) vals.push("");

    vals.forEach((val, idx) => {
      const wrap = document.createElement("div");
      const id = `msg_${idx}`;
      wrap.innerHTML = `
        <label for="${id}">Message ${idx + 1}</label>
        <textarea id="${id}" rows="2" maxlength="200" placeholder="Enter message...">${val}</textarea>
      `;
      grid.appendChild(wrap);
    });

    updateCount();
    qsa("textarea", grid).forEach(t => t.addEventListener("input", updateCount));
  }

  function updateCount() {
    const vals = getMessagesFromUI();
    const used = vals.filter(v => v.trim().length > 0).length;
    qs("#msgCount").textContent = String(used);
  }

  function getMessagesFromUI() {
    return qsa("#messagesGrid textarea").map(t => t.value);
  }

  async function loadMessages() {
    try {
      const r = await fetch("/api/messages");
      if (!r.ok) throw new Error(await r.text());
      const d = await r.json();
      buildGrid((d.messages || []).map(String));
    } catch (e) {
      buildGrid([]);
      showToast(e.message || "Failed to load messages.");
    }
  }

  async function saveMessages() {
    const msgs = getMessagesFromUI()
      .map(s => (s || "").trim())
      .filter(Boolean)
      .slice(0, 10);
    try {
      qs("#btnSaveMessages").disabled = true;
      const r = await fetch("/api/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: msgs }),
      });
      if (!r.ok) throw new Error(await r.text());
      showToast("Messages saved.");
      updateCount();
    } catch (e) {
      showToast(e.message || "Failed to save messages.");
    } finally {
      qs("#btnSaveMessages").disabled = false;
    }
  }

  function clearAll() {
    qsa("#messagesGrid textarea").forEach(t => t.value = "");
    updateCount();
  }

  function loadExamples() {
    const examples = [
      "Following up regarding your engine replacement options.",
      "Could you confirm the vehicle details so I can advise properly?",
      "I want to review availability and lead times with you.",
      "Do you prefer new, remanufactured, or used engines?",
      "I am calling about your recent inquiry on engine sourcing.",
      "Can we verify compatibility with your VIN or engine code?",
      "Let us go over warranty coverage and exclusions.",
      "Do you have a preferred timeline for the swap?",
      "Are there logistics constraints I should be aware of?",
      "Would you like a written quote to review today?"
    ];
    buildGrid(examples);
    updateCount();
    showToast("Loaded example messages.");
  }

  function bind() {
    qs("#btnSaveMessages").addEventListener("click", saveMessages);
    qs("#btnClearAll").addEventListener("click", clearAll);
    qs("#btnLoadExamples").addEventListener("click", loadExamples);
  }

  document.addEventListener("DOMContentLoaded", () => {
    bind();
    loadMessages();
  });
})();
