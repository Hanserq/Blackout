(() => {
  const HOST_ID   = 'particles';
  const JS_PATH   = 'particles.min.js';
  const CFG_PATH  = 'particlesjs-config.json';

  // Ensure container exists
  let host = document.getElementById(HOST_ID);
  if (!host) {
    host = document.createElement('div');
    host.id = HOST_ID;
    host.setAttribute('aria-hidden', 'true');
    document.body.prepend(host);
  }

  const prefersReduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const isMobile = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent) || window.innerWidth < 1024;
  let scriptLoaded = !!window.particlesJS;
  let starting = false;

  function applyParticlesClass(on) {
    document.body.classList.toggle('particles-on', !!on);
  }

  function destroyParticles() {
    try {
      if (window.pJSDom && window.pJSDom.length) {
        window.pJSDom.forEach(p => p?.pJS?.fn?.vendors?.destroypJS?.());
        window.pJSDom.length = 0;
      }
      host.querySelectorAll('canvas').forEach(c => c.remove());
    } catch {}
  }

  function tuneConfig(cfg) {
    // Desktop-only → no mobile cutoffs
    cfg.interactivity ??= {};
    cfg.interactivity.events ??= {};
    cfg.interactivity.events.onhover = { enable: true, mode: "grab" };
    cfg.interactivity.events.onclick = { enable: true, mode: "repulse" };
    return cfg;
  }
  async function startParticles() {
  if (starting || prefersReduced) return;
  starting = true;

  try {
    if (!scriptLoaded) {
      await new Promise((res, rej) => {
        const s = document.createElement('script');
        s.src = JS_PATH; s.async = true;
        s.onload = () => { scriptLoaded = true; res(); };
        s.onerror = () => rej(new Error('Failed to load particles.min.js'));
        document.head.appendChild(s);
      });
    }

    // Wait until particlesJS is really available
    if (typeof window.particlesJS !== "function") {
      console.error("[particles] engine missing after load");
      return;
    }

    const resp = await fetch(CFG_PATH, { cache: "force-cache" });
    const userCfg = await resp.json();
    const tuned   = tuneConfig(userCfg);

    destroyParticles();
    window.particlesJS(HOST_ID, tuned);
    applyParticlesClass(true);

    } catch (e) {
      console.error("[particles] init failed:", e);
      enabled = false; setPref(false); setButton();
    } finally {
      starting = false;
    }
  }
 
  // Start immediately (desktop only)
  startParticles();

  // Retune on resize/orientation
  let t;
  addEventListener('resize', () => {
    clearTimeout(t);
    t = setTimeout(startParticles, 250);
  });
})();
