(function () {
  "use strict";

  const canvas = document.getElementById("matrix-canvas");
  if (!canvas) return;

  const ctx = canvas.getContext("2d", { alpha: true });
  if (!ctx) return;

  let width = 0;
  let height = 0;

  let columns = 0;
  let drops = [];
  let fontSize = 16;

  const charset = "01";
  const shades = [
    "rgba(126, 200, 255, 0.92)", // light blue
    "rgba(42, 116, 199, 0.85)",  // dark blue
    "rgba(154, 211, 255, 0.94)", // light blue
  ];

  function resize() {
    width = canvas.clientWidth | 0;
    height = canvas.clientHeight | 0;
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
    ctx.fillStyle = "rgba(0, 0, 0, 0.07)";
    ctx.fillRect(0, 0, width, height);

    for (let i = 0; i < columns; i++) {
      const x = i * fontSize;
      const y = drops[i] * fontSize;

      const shadeIdx = Math.abs((i + drops[i])) % 3;
      ctx.fillStyle = shades[shadeIdx];
      const ch = charset.charAt((Math.random() * charset.length) | 0);
      ctx.fillText(ch, x, y);

      if (y > height && Math.random() > 0.975) {
        drops[i] = Math.floor(Math.random() * -30);
      } else {
        drops[i]++;
      }
    }

    requestAnimationFrame(step);
  }

  resize();
  step();

  let resizeTimeout = null;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(resize, 120);
  });
})();
