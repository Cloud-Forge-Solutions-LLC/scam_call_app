(function () {
  "use strict";

  const STORAGE_KEY = "matrixRainState.v2";

  function getCanvas() {
    return document.getElementById("matrix-canvas");
  }

  const canvas = getCanvas();
  if (!canvas) return;

  const ctx = canvas.getContext("2d", { alpha: true });

  let width = 0;
  let height = 0;

  // Columns for the rain
  let columns = 0;
  let drops = [];
  let fontSize = 16;
  const charset = "01";

  // Helpers to read theme variables
  function readTheme() {
    const styles = getComputedStyle(document.documentElement);
    const lead = styles.getPropertyValue("--matrix-lead").trim(); // "r g b" (space-separated)
    const trailAlphaStr = styles.getPropertyValue("--matrix-trail-alpha").trim();
    const trailAlpha = Math.max(0, Math.min(1, parseFloat(trailAlphaStr || "0.07"))) || 0.07;

    // Parse "r g b" or "r,g,b"
    let r = 40, g = 255, b = 180; // default green-teal
    if (lead) {
      const parts = lead.replace(/,/g, " ").split(/\s+/).map(Number).filter((n) => Number.isFinite(n));
      if (parts.length >= 3) {
        r = parts[0]; g = parts[1]; b = parts[2];
      }
    }
    return { r, g, b, trailAlpha };
  }

  // State persistence
  function saveState() {
    try {
      const payload = {
        savedAt: Date.now(),
        columns,
        fontSize,
        drops, // array of numbers (row indices)
        viewportW: window.innerWidth,
        viewportH: window.innerHeight,
      };
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
    } catch {
      // ignore storage failures
    }
  }

  function loadState() {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || !Array.isArray(parsed.drops)) return null;

      // If the state is too old, skip (navigation long enough that continuity is less noticeable)
      const ageMs = Date.now() - (parsed.savedAt || 0);
      if (ageMs > 15000) return null;

      return parsed;
    } catch {
      return null;
    }
  }

  function mapDropsToNewColumns(prevDrops, prevCols, nextCols) {
    if (!Array.isArray(prevDrops) || prevCols <= 0 || nextCols <= 0) {
      return new Array(nextCols).fill(0).map(() => Math.floor(Math.random() * -40));
    }
    const mapped = new Array(nextCols);
    for (let i = 0; i < nextCols; i++) {
      const src = Math.floor((i * prevCols) / nextCols);
      const val = prevDrops[src];
      mapped[i] = Number.isFinite(val) ? val : Math.floor(Math.random() * -40);
    }
    return mapped;
  }

  // Resize while attempting to preserve drops continuity
  function resize(tryPreserve = true) {
    width = canvas.clientWidth | 0;
    height = canvas.clientHeight | 0;
    // Adapt for device pixel ratio for crisp rendering
    const ratio = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
    canvas.width = Math.floor(width * ratio);
    canvas.height = Math.floor(height * ratio);
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);

    const prevFont = fontSize;
    const prevCols = columns;
    const prevDrops = drops;

    fontSize = Math.max(14, Math.min(22, Math.round(width / 90)));
    ctx.font = `${fontSize}px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace`;

    columns = Math.ceil(width / fontSize);

    if (tryPreserve && Array.isArray(prevDrops) && prevDrops.length > 0) {
      // Map previous columns to new columns; adjust for font size change
      const sizeRatio = prevFont > 0 ? (prevFont / fontSize) : 1;
      const adjusted = prevDrops.map((v) => v * sizeRatio);
      drops = mapDropsToNewColumns(adjusted, prevCols, columns);
    } else {
      drops = new Array(columns).fill(0).map(() => Math.floor(Math.random() * -40));
    }
  }

  function step() {
    const { r, g, b, trailAlpha } = readTheme();

    // Fade the canvas slightly to create a trail effect
    ctx.fillStyle = `rgba(0, 0, 0, ${trailAlpha})`;
    ctx.fillRect(0, 0, width, height);

    // Draw cascading digits
    for (let i = 0; i < columns; i++) {
      const x = i * fontSize;
      const y = drops[i] * fontSize;

      // Bright leading character (theme-controlled)
      ctx.fillStyle = `rgba(${r}, ${g}, ${b}, 0.85)`;
      const ch = charset.charAt((Math.random() * charset.length) | 0);
      ctx.fillText(ch, x, y);

      // After reaching bottom, restart at random position with a pause
      if (y > height && Math.random() > 0.975) {
        drops[i] = Math.floor(Math.random() * -30);
      } else {
        drops[i]++;
      }
    }

    requestAnimationFrame(step);
  }

  // Attempt to restore previous session state to avoid visual restart
  const restored = loadState();
  resize(false);
  if (restored && Number.isFinite(restored.columns) && Array.isArray(restored.drops)) {
    // Align restored state to current sizing
    const sizeRatio = restored.fontSize > 0 ? (restored.fontSize / fontSize) : 1;
    const adjusted = restored.drops.map((v) => v * sizeRatio);
    drops = mapDropsToNewColumns(adjusted, restored.columns, Math.ceil(width / fontSize));
    columns = drops.length;
  } else {
    // Fresh seed
    drops = new Array(columns).fill(0).map(() => Math.floor(Math.random() * -40));
  }

  // Start animation
  step();

  // Handle resize with preservation
  let resizeTimeout = null;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(() => resize(true), 120);
  });

  // Save state on navigation or tab hide
  window.addEventListener("pagehide", saveState, { passive: true });
  window.addEventListener("beforeunload", saveState, { passive: true });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") saveState();
  }, { passive: true });
})();
