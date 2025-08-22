(function () {
  "use strict";

  const qs = (s, c = document) => c.querySelector(s);

  function showToast(msg, ms = 2800) {
    const el = qs("#toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.add("toast--show");
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => el.classList.remove("toast--show"), ms);
  }

  const els = {
    voice: null,
    lang: null,
    rate: null,
    rateVal: null,
    pitch: null,
    pitchVal: null,
    volume: null,
    volumeVal: null,
    greetPause: null,
    respPause: null,
    betweenPause: null,
    save: null,
    randomize: null,
  };

  function bind() {
    els.voice = qs("#voiceSelect");
    els.lang = qs("#languageSelect");
    els.rate = qs("#rateInput");
    els.rateVal = qs("#rateValue");
    els.pitch = qs("#pitchInput");
    els.pitchVal = qs("#pitchValue");
    els.volume = qs("#volumeInput");
    els.volumeVal = qs("#volumeValue");
    els.greetPause = qs("#greetPauseInput");
    els.respPause = qs("#respPauseInput");
    els.betweenPause = qs("#betweenPauseInput");
    els.save = qs("#btnSaveSpeech");
    els.randomize = qs("#btnRandomize");

    els.rate.addEventListener("input", () => els.rateVal.textContent = `${els.rate.value}%`);
    els.pitch.addEventListener("input", () => els.pitchVal.textContent = `${els.pitch.value} st`);
    els.volume.addEventListener("input", () => els.volumeVal.textContent = `${els.volume.value} dB`);

    els.save.addEventListener("click", saveSettings);
    els.randomize.addEventListener("click", randomizeAll);
  }

  function populateOptions(voices, languages) {
    els.voice.innerHTML = voices.map(v => `<option value="${v}">${v}</option>`).join("");
    els.lang.innerHTML = languages.map(l => `<option value="${l}">${l}</option>`).join("");
  }

  async function loadSettings() {
    try {
      const r = await fetch("/api/speech-settings");
      if (!r.ok) throw new Error(await r.text());
      const d = await r.json();
      populateOptions(d.voices || [], d.languages || []);

      const v = d.values || {};
      setUI(v);
    } catch (e) {
      showToast(e.message || "Failed to load settings.");
    }
  }

  function setUI(v) {
    if (v.tts_voice) els.voice.value = v.tts_voice;
    if (v.tts_language) els.lang.value = v.tts_language;

    els.rate.value = v.tts_rate_percent ?? 100;
    els.rate.dispatchEvent(new Event("input"));

    els.pitch.value = v.tts_pitch_semitones ?? 0;
    els.pitch.dispatchEvent(new Event("input"));

    els.volume.value = v.tts_volume_db ?? 0;
    els.volume.dispatchEvent(new Event("input"));

    els.greetPause.value = v.greeting_pause_seconds ?? 1.0;
    els.respPause.value = v.response_pause_seconds ?? 0.5;
    els.betweenPause.value = v.between_phrases_pause_seconds ?? 1.0;
  }

  async function saveSettings() {
    const payload = {
      tts_voice: els.voice.value,
      tts_language: els.lang.value,
      tts_rate_percent: Number(els.rate.value),
      tts_pitch_semitones: Number(els.pitch.value),
      tts_volume_db: Number(els.volume.value),
      greeting_pause_seconds: Number(els.greetPause.value),
      response_pause_seconds: Number(els.respPause.value),
      between_phrases_pause_seconds: Number(els.betweenPause.value),
    };
    try {
      els.save.disabled = true;
      const r = await fetch("/api/speech-settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!r.ok) throw new Error(await r.text());
      showToast("Speech settings saved.");
    } catch (e) {
      showToast(e.message || "Failed to save.");
    } finally {
      els.save.disabled = false;
    }
  }

  function randomizeAll() {
    const voiceOpts = Array.from(els.voice.options).map(o => o.value);
    const langOpts = Array.from(els.lang.options).map(o => o.value);
    const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

    els.voice.value = pick(voiceOpts);
    els.lang.value = pick(langOpts);

    // Favor natural ranges
    els.rate.value = [85, 90, 95, 100, 105, 110, 115][Math.floor(Math.random() * 7)];
    els.rate.dispatchEvent(new Event("input"));

    els.pitch.value = [-3, -2, -1, 0, 1, 2, 3][Math.floor(Math.random() * 7)];
    els.pitch.dispatchEvent(new Event("input"));

    els.volume.value = [-2, -1, 0, 1, 2][Math.floor(Math.random() * 5)];
    els.volume.dispatchEvent(new Event("input"));

    els.greetPause.value = [0.5, 0.8, 1.0, 1.2, 1.5][Math.floor(Math.random() * 5)];
    els.respPause.value = [0.3, 0.5, 0.7, 1.0][Math.floor(Math.random() * 4)];
    els.betweenPause.value = [0.7, 1.0, 1.2, 1.5][Math.floor(Math.random() * 4)];

    showToast("Randomized settings.");
  }

  document.addEventListener("DOMContentLoaded", () => {
    bind();
    loadSettings();
  });
})();
