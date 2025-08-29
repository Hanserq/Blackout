// argon2.worker.js
/* global importScripts, self */
let ready = false;
let config = null;

// Load config first
self.addEventListener('message', (e) => {
  if (e.data && e.data.type === 'ping') {
    // no-op; main thread probes readiness
  }
});

(async () => {
  try {
    // Load config and argon2 runtime
    importScripts('argon2.config.js');        // sets self.ARGON2_PRESETS
    config = self.ARGON2_PRESETS;

    // Load argon2 runtime (expects argon2.min.js at root that auto-loads argon2.wasm)
    importScripts('argon2.min.js');           // provides global "argon2" object

    ready = true;
    self.dispatchEvent(new Event('argon2-ready'));
    // Also notify the page (will bubble)
    setTimeout(() => self.postMessage({ type: 'ready' }), 0);
  } catch (err) {
    console.error('Argon2 worker failed to initialize:', err);
  }
})();

self.addEventListener('message', async (e) => {
  const d = e.data || {};
  if (d.type !== 'derive') return;
  const { id, pass, salt, mode, caps } = d;

  if (!ready || !self.argon2) {
    self.postMessage({ id, ok: false, error: 'Argon2 engine not loaded' });
    return;
  }

  try {
    const preset = pickPreset(mode, caps);
    // argon2 expects Array or TypedArray
    const res = await self.argon2.hash({
      pass: new Uint8Array(pass),
      salt: new Uint8Array(salt),
      type: self.argon2.ArgonType.Argon2id,
      hashLen: 32,
      time: preset.t,
      mem: preset.m * 1024,   // KiB
      parallelism: preset.p,
      version: 0x13
    });
    // res.hash is Uint8Array(32) in common builds
    self.postMessage({ id, ok: true, key: Array.from(res.hash) });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err && err.message || err) });
  }
});

function pickPreset(mode, caps){
  const mobile = !!(caps && caps.mobile);
  const dm = (caps && caps.memGiB) || 0;  // 0=unknown: assume low
  // Maximum memory cap per device class (MiB)
  const MAX_DESKTOP = dm >= 16 ? 1024 : dm >= 8 ? 512 : 256;
  const MAX_MOBILE  = 128;

  const presets = {
    argon2id_interactive: { m: Math.min( mobile ? 64 : 64,            mobile ? MAX_MOBILE : MAX_DESKTOP ), t: 2, p: 1 },
    argon2id_balanced:    { m: Math.min( mobile ? 96 : 256,           mobile ? MAX_MOBILE : MAX_DESKTOP ), t: 3, p: mobile ? 1 : 2 },
    argon2id_high:        { m: Math.min( 512,                          mobile ? MAX_MOBILE : MAX_DESKTOP ), t: 3, p: 2 }
  };
  let p = presets[mode] || presets.argon2id_balanced;
  // Clamp if unknown device memory
  if (mobile && p.m > MAX_MOBILE) p = { ...p, m: MAX_MOBILE };
  return p;
}
