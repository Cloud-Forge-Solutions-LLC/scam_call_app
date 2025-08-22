/**
 * Matrix Digital Rain Animation
 * Creates a falling 0/1 animation background
 */
(function() {
  'use strict';

  // Check for reduced motion preference
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    return;
  }

  let canvas, ctx, columns, drops, chars;
  let animationId;

  function initMatrix() {
    // Create canvas
    canvas = document.createElement('canvas');
    canvas.className = 'matrix-canvas';
    ctx = canvas.getContext('2d');
    
    // Create container
    const container = document.createElement('div');
    container.className = 'matrix-container';
    container.appendChild(canvas);
    document.body.appendChild(container);

    // Character set - primarily 0 and 1 with occasional other digits
    chars = ['0', '1', '0', '1', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
    
    resizeCanvas();
    initDrops();
    startAnimation();
  }

  function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const fontSize = 14;
    ctx.font = fontSize + 'px "JetBrains Mono", "Courier New", monospace';
    
    columns = Math.floor(canvas.width / fontSize);
    
    // Reinitialize drops if canvas was resized
    if (columns > 0) {
      initDrops();
    }
  }

  function initDrops() {
    drops = [];
    for (let i = 0; i < columns; i++) {
      drops[i] = Math.random() * canvas.height;
    }
  }

  function draw() {
    // Semi-transparent black background to create fading effect
    ctx.fillStyle = 'rgba(11, 15, 20, 0.1)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Matrix green color with slight variation
    ctx.fillStyle = '#00ff41';
    
    for (let i = 0; i < drops.length; i++) {
      // Pick a random character
      const char = chars[Math.floor(Math.random() * chars.length)];
      
      // Draw the character
      ctx.fillText(char, i * 14, drops[i]);
      
      // Reset drop to top if it goes below screen or randomly (creates spacing)
      if (drops[i] > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      
      // Move drop down
      drops[i] += 14;
    }
  }

  function animate() {
    draw();
    animationId = requestAnimationFrame(animate);
  }

  function startAnimation() {
    if (animationId) {
      cancelAnimationFrame(animationId);
    }
    animate();
  }

  function stopAnimation() {
    if (animationId) {
      cancelAnimationFrame(animationId);
      animationId = null;
    }
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initMatrix);
  } else {
    initMatrix();
  }

  // Handle window resize
  window.addEventListener('resize', resizeCanvas);

  // Handle visibility change to pause/resume animation
  document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
      stopAnimation();
    } else {
      startAnimation();
    }
  });

  // Export for potential external control
  window.MatrixAnimation = {
    start: startAnimation,
    stop: stopAnimation
  };
})();