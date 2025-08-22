(function () {
  "use strict";

  const canvas = document.getElementById("matrix-canvas");
  if (!canvas) return;

  const ctx = canvas.getContext("2d", { alpha: true });

  let width = 0;
  let height = 0;

  // Columns for the rain
  let columns = 0;
  let drops = [];
  let fontSize = 16;
  const charset = "01";

  function resize() {
    width = canvas.clientWidth | 0;
    height = canvas.clientHeight | 0;
    // Adapt for device pixel ratio for crisp rendering
    const ratio = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
    canvas.width = Math.floor(width * ratio);
    canvas.height = Math.floor(height * ratio);
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);

    fontSize = Math.max(14, Math.min(22, Math.round(width / 90)));
    ctx.font = `${fontSize}px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace`;

    columns = Math.ceil(width / fontSize);
    drops = new Array(columns).fill(0).map(() => Math.floor(Math.random() * -40));
  }

  function step() {
    // Fade the canvas slightly to create a trail effect
    ctx.fillStyle = "rgba(0, 0, 0, 0.07)";
    ctx.fillRect(0, 0, width, height);

    // Draw cascading digits
    for (let i = 0; i < columns; i++) {
      const x = i * fontSize;
      const y = drops[i] * fontSize;

      // Bright leading character
      ctx.fillStyle = "rgba(40, 255, 180, 0.85)";
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

  // Initial setup
  resize();
  step();

  // Handle resize
  let resizeTimeout = null;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(resize, 120);
  });
})();
