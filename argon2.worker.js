// argon2.worker.js
/* global importScripts, self */
let ready = false;
let config = null;

// Let the main thread "ping" us (optional)
self.addEventListener('message', (e) => {
  if (e.data && e.data.type === 'ping') {
    if (ready) self.postMessage({ type: 'ready' });
  }
});

(async () => {
  try {
    // 1) Load config (defines self.ARGON2_PRESETS)
    importScripts('argon2.config.js');
    config = self.ARGON2_PRESETS;

    // 2) Load Argon2 runtime — this is the *bundled* build (no separate .wasm fetch)
    importScripts('argon2.min.js');  // exposes global self.argon2

    ready = true;

    // Tell the page we’re good to go
    self.postMessage({ type: 'ready' });
  } catch (err) {
    // Surface init errors to the page
    self.postMessage({ type: 'error', error: String(err && err.message || err) });
  }
})();

// KDF requests from the page
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

    // Ensure TypedArrays
    const passU8 = pass instanceof ArrayBuffer ? new Uint8Array(pass) : new Uint8Array(pass);
    const saltU8 = salt instanceof ArrayBuffer ? new Uint8Array(salt) : new Uint8Array(salt);

    // argon2-browser API
    const res = await self.argon2.hash({
      pass: passU8,
      salt: saltU8,
      type: self.argon2.ArgonType.Argon2id,
      hashLen: 32,
      time: preset.t,
      mem: preset.m * 1024,   // MiB -> KiB
      parallelism: preset.p,
      version: 0x13
    });

    // Return raw key bytes (array for structured clone)
    self.postMessage({ id, ok: true, key: Array.from(res.hash) });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err && err.message || err) });
  }
});

// Presets with conservative device caps
function pickPreset(mode, caps){
  const mobile = !!(caps && caps.mobile);
  const dm = (caps && caps.memGiB) || 0; // Chromium only
  const MAX_DESKTOP = dm >= 16 ? 1024 : dm >= 8 ? 512 : 256; // MiB
  const MAX_MOBILE  = 128; // MiB

  const presets = {
    argon2id_interactive: { m: Math.min(mobile ? 64 : 64,  mobile ? MAX_MOBILE : MAX_DESKTOP), t: 2, p: 1 },
    argon2id_balanced:    { m: Math.min(mobile ? 96 : 256, mobile ? MAX_MOBILE : MAX_DESKTOP), t: 3, p: mobile ? 1 : 2 },
    argon2id_high:        { m: Math.min(512,                 mobile ? MAX_MOBILE : MAX_DESKTOP), t: 3, p: 2 }
  };
  let p = presets[mode] || presets.argon2id_balanced;
  if (mobile && p.m > MAX_MOBILE) p = { ...p, m: MAX_MOBILE };
  return p;
}
