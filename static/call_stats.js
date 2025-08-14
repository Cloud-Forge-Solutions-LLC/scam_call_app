// Call statistics and right-side graphic for scam call app
// Provides: fetchAndRenderStats, updateStatsOnNewCall
// Requires: #statsGraphic element in DOM

(function () {
  "use strict";

  let stats = {
    callCount: 0,
    timeWastedSeconds: 0,
    lastCallSid: null,
  };

  // Format duration as "Xm Ys"
  function formatDuration(seconds) {
    const s = Math.floor(seconds || 0);
    const m = Math.floor(s / 60);
    const r = s % 60;
    if (m > 0) return `${m}m ${r}s`;
    return `${r}s`;
  }

  // Render stats graphic in #statsGraphic
  function renderStatsGraphic() {
    const el = document.getElementById("statsGraphic");
    if (!el) return;
    el.innerHTML = `
      <div class="stats-panel">
        <div class="stats-title">Impact</div>
        <div class="stats-row">
          <div class="stats-label">Calls placed</div>
          <div class="stats-value" id="statsCallCount">${stats.callCount}</div>
        </div>
        <div class="stats-row">
          <div class="stats-label">Scammer time wasted</div>
          <div class="stats-value" id="statsTimeWasted">${formatDuration(stats.timeWastedSeconds)}</div>
        </div>
      </div>
    `;
  }

  // Fetch call stats from backend history API
  async function fetchAndRenderStats() {
    try {
      const r = await fetch("/api/history");
      if (!r.ok) return;
      const data = await r.json();
      let calls = Array.isArray(data.calls) ? data.calls : [];
      stats.callCount = calls.length;
      stats.timeWastedSeconds = calls.reduce((sum, c) => sum + (c.duration_seconds || 0), 0);
      renderStatsGraphic();
    } catch {
      // ignore load errors
    }
  }

  // Update stats on new call (called from main logic)
  function updateStatsOnNewCall(callSid, durationSeconds) {
    if (callSid && callSid !== stats.lastCallSid) {
      stats.callCount += 1;
      stats.lastCallSid = callSid;
    }
    if (durationSeconds && durationSeconds > 0) {
      stats.timeWastedSeconds += durationSeconds;
    }
    renderStatsGraphic();
  }

  // Expose globally
  window.callStats = {
    fetchAndRenderStats,
    updateStatsOnNewCall,
  };
})();
