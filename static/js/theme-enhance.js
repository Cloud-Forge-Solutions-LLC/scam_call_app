/* theme-enhance.js
   Small visual enhancement script:
   - animates the --accent CSS variable with a gentle hue shift
   - mouse parallax for decorative background layers
   - button hover pulse (non-disruptive)
   - honors prefers-reduced-motion
*/
(function () {
  "use strict";

  const doc = document.documentElement;
  const prefersReduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Initial accent color (kept in sync with CSS variable)
  let baseHue = 164; // starting hue near your green-teal (#25c2a0)
  let hueDir = 1;
  let lastFrame = performance.now();
  const hueSpeed = 0.0045; // degrees per ms; very slow

  function clampHue(h) {
    if (h < 0) return 360 + (h % 360);
    if (h >= 360) return h % 360;
    return h;
  }

  function updateAccent(ts) {
    if (prefersReduce) return;
    const dt = Math.max(0, ts - lastFrame);
    lastFrame = ts;
    // gentle oscillation rather than steady spin
    baseHue += hueDir * hueSpeed * dt;
    if (baseHue > 200 || baseHue < 140) hueDir *= -1;
    const hue = clampHue(baseHue);
    // convert HSL to CSS color and apply
    const sat = 62;
    const light = 56;
    const color = `hsl(${Math.round(hue)} ${sat}% ${light}%)`;
    doc.style.setProperty("--accent", color);
    // small complementary glow for accent-contrast if needed
    const contrast = `hsl(${Math.round((hue + 180) % 360)} 20% 8%)`;
    doc.style.setProperty("--accent-contrast", contrast);
    // loop
    requestAnimationFrame(updateAccent);
  }

  // Parallax effect for background elements (.background-effects children)
  function initParallax() {
    const bg = document.querySelector(".background-effects");
    if (!bg || prefersReduce) return;
    const layers = {
      grid: bg.querySelector(".grid"),
      glow: bg.querySelector(".glow"),
      scanlines: bg.querySelector(".scanlines"),
    };
    let rect = bg.getBoundingClientRect();
    window.addEventListener("resize", () => {
      rect = bg.getBoundingClientRect();
    });
    function onMove(e) {
      const x = (e.clientX - rect.left) / rect.width - 0.5;
      const y = (e.clientY - rect.top) / rect.height - 0.5;
      if (layers.grid) layers.grid.style.transform = `translate3d(${x * 6}px, ${y * 6}px, 0) rotate(${x * 2}deg)`;
      if (layers.glow) layers.glow.style.transform = `translate3d(${x * 10}px, ${y * 8}px, 0)`;
      if (layers.scanlines) layers.scanlines.style.transform = `translate3d(${x * 2}px, ${y * 2}px, 0)`;
    }
    window.addEventListener("mousemove", onMove, { passive: true });
    window.addEventListener("touchmove", (ev) => {
      if (!ev.touches || ev.touches.length === 0) return;
      onMove(ev.touches[0]);
    }, { passive: true });
  }

  // Button hover pulse handling (non-invasive)
  function initButtonPulse() {
    if (prefersReduce) return;
    document.addEventListener("mouseover", (ev) => {
      const btn = ev.target.closest && ev.target.closest(".btn");
      if (!btn) return;
      btn.style.transition = "box-shadow 220ms ease, transform 160ms ease";
      btn.style.boxShadow = "0 14px 44px rgba(0,0,0,0.45), 0 0 28px rgba(37,194,160,0.06)";
    });
    document.addEventListener("mouseout", (ev) => {
      const btn = ev.target.closest && ev.target.closest(".btn");
      if (!btn) return;
      btn.style.boxShadow = "";
    });
  }

  // small helper: insert a scanline overlay in the DOM (global)
  function ensureGlobalScanlines() {
    if (document.querySelector(".scanline-overlay")) return;
    const div = document.createElement("div");
    div.className = "scanline-overlay";
    document.body.appendChild(div);
  }

  // Initialize on DOM ready
  document.addEventListener("DOMContentLoaded", () => {
    // start accent animation
    requestAnimationFrame(updateAccent);
    // parallax for background-effects block
    initParallax();
    // hover pulse for buttons
    initButtonPulse();
    // global scanline
    ensureGlobalScanlines();
    // micro-interaction: gentle header logo glow pulse via CSS variable animation
    const brandMark = document.querySelector(".app-title .brand-mark, .brand .logo");
    if (brandMark && !prefersReduce) {
      let pulseOn = false;
      setInterval(() => {
        pulseOn = !pulseOn;
        brandMark.style.transition = "filter 680ms ease, transform 680ms ease";
        brandMark.style.transform = pulseOn ? "scale(1.02)" : "scale(1)";
        brandMark.style.filter = pulseOn ? "drop-shadow(0 14px 30px rgba(37,194,160,0.12))" : "drop-shadow(0 6px 18px rgba(0,0,0,0.6))";
      }, 2800);
    }
  });

})();
