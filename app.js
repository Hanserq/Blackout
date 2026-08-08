/* Blackout Logic: UI Events, Crypto, Compression and PNG Steganography */
'use strict';

const UI = {
  fileIn: document.getElementById('fileIn'),
  password: document.getElementById('password'),
  mode: document.getElementById('mode'),
  goBtn: document.getElementById('goBtn'),
  status: document.getElementById('status'),
  lastOut: document.getElementById('lastOut'),
  downloadBtn: document.getElementById('downloadBtn'),
  clearBtn: document.getElementById('clearBtn'),
  reencryptBtn: document.getElementById('reencryptBtn'),
  inspectBtn: document.getElementById('inspectBtn'),
  metaInspectBtn: document.getElementById('metaInspectBtn'),
  viewRecoveryBtn: document.getElementById('viewRecoveryBtn'),
  coverIn: document.getElementById('coverIn'),
  coverLabel: document.getElementById('coverLabel'),
  coverDrop: document.getElementById('coverDrop'),
  makeBlackCover: document.getElementById('makeBlackCover'),
  useDemoCover: document.getElementById('useDemoCover'),
  outputName: document.getElementById('outputName'),
  fileInfo: document.getElementById('fileInfo'),
  coverInfo: document.getElementById('coverInfo'),
  textInput: document.getElementById('textInput'),
  textLabel: document.getElementById('textLabel'),
  textWrap: document.getElementById('textWrap'),
  copyMsgBtn: document.getElementById('copyMsgBtn'),
  clearTextBtn: document.getElementById('clearTextBtn'),
  genPassBtn: document.getElementById('genPassBtn'),
  strengthFill: document.getElementById('strengthFill'),
  strengthLabel: document.getElementById('strengthLabel'),
  progressWrap: document.getElementById('progressWrap'),
  progressBar: document.querySelector('.progress-bar'),
  progressLabel: document.getElementById('progressLabel'),
  saveCloudBtn: document.getElementById('saveCloudBtn'),
  importCloudBtn: document.getElementById('importCloudBtn'),
  cloudModal: document.getElementById('cloudModal'),
  closeCloudModal: document.getElementById('closeCloudModal'),
  cancelCloudModalBtn: document.getElementById('cancelCloudModalBtn'),
  confirmCloudSaveBtn: document.getElementById('confirmCloudSaveBtn'),
  cloudContextNote: document.getElementById('cloudContextNote'),
  cloudModalStatus: document.getElementById('cloudModalStatus'),
  gdriveAuthWrap: document.getElementById('gdriveAuthWrap'),
  gdriveToken: document.getElementById('gdriveToken'),
  gdriveSignInBtn: document.getElementById('gdriveSignInBtn'),
  gdriveStatusText: document.getElementById('gdriveStatusText'),
  gdriveClientId: document.getElementById('gdriveClientId'),
};

const GO_LABEL = UI.goBtn.textContent;
const APP_VERSION = '2.3.0';

// ---------- Support / diagnostics ----------

function supportProblems() {
  const out = [];
  if (!window.isSecureContext) out.push('This tool requires a secure context (HTTPS or localhost).');
  if (!window.crypto || !window.crypto.subtle) out.push('Web Crypto API (crypto.subtle) is unavailable in this browser.');
  if (!('CompressionStream' in window) || !('DecompressionStream' in window)) out.push('CompressionStream / DecompressionStream are not supported here. Use a recent Chrome, Edge, Firefox, or Safari (16.4+).');
  return out;
}

function logStatus(txt, isError=false) {
  UI.status.style.display='block';
  UI.status.textContent = txt;
  UI.status.style.color = isError ? '#ffb3b3' : '';
}

function hideStatus(){ UI.status.style.display='none' }

// ---------- Console output (timestamped history) ----------

const consoleLogs = [];

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function logToConsole(msg, kind='info') {
  const t = new Date().toLocaleTimeString([], {hour12: false});
  consoleLogs.push({t, msg: String(msg), kind});
  if (consoleLogs.length > 120) consoleLogs.shift();
  UI.lastOut.innerHTML = consoleLogs
    .map(e => '<div class="log-entry log-' + e.kind + '"><span class="log-time">[' + e.t + ']</span>' + escapeHtml(e.msg) + '</div>')
    .join('');
  UI.lastOut.scrollTop = UI.lastOut.scrollHeight;
}

function clearConsole() {
  consoleLogs.length = 0;
  UI.lastOut.innerHTML = '<div class="log-empty">No output yet.</div>';
}

// ---------- Binary helpers ----------

function readU32(bytes, off) { return (bytes[off]<<24) | (bytes[off+1]<<16) | (bytes[off+2]<<8) | (bytes[off+3]); }
function writeU32(v) { return new Uint8Array([(v>>>24)&255,(v>>>16)&255,(v>>>8)&255,v&255]); }

// ---------- Filename helpers ----------

// Strip path separators, illegal characters and control chars before download.
function sanitizeFileName(name) {
  return String(name || 'output')
    .replace(/[\\/:*?"<>|\x00-\x1f]/g, '_')
    .replace(/\s+/g, ' ')
    .trim() || 'output';
}

function stripExt(name) {
  const i = name.lastIndexOf('.');
  return i > 0 ? name.slice(0, i) : name;
}

function ensureExt(name, ext) {
  return /\.\w+$/.test(name) ? name : name + ext;
}

// Use a user-provided output name (auto-appending `ext` when missing),
// otherwise fall back to the mode-specific smart default.
function customOrDefault(custom, fallback, ext) {
  const c = String(custom || '').trim();
  if (!c) return fallback;
  return ext ? ensureExt(c, ext) : c;
}

async function deriveKey(password, salt, iterations=150000) {
  const enc = new TextEncoder();
  const pwKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    {name:'PBKDF2', salt: salt, iterations: iterations, hash:'SHA-256'},
    pwKey,
    {name:'AES-GCM', length: 256},
    true,
    ['encrypt','decrypt']
  );
  return key;
}

function randBytes(n){ const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }

// ---------- Progress indicator ----------

function setProgress(label, pct) {
  UI.progressWrap.style.display = 'block';
  UI.progressWrap.setAttribute('aria-valuetext', label || 'Working');
  UI.progressLabel.textContent = label || 'Working…';
  if (Number.isFinite(pct)) {
    UI.progressBar.classList.add('determinate');
    UI.progressBar.style.width = Math.max(0, Math.min(100, pct)) + '%';
    UI.progressWrap.setAttribute('aria-valuenow', String(Math.round(pct)));
  } else {
    UI.progressBar.classList.remove('determinate');
    UI.progressBar.style.width = '';
    UI.progressWrap.removeAttribute('aria-valuenow');
  }
}

function endProgress() {
  UI.progressWrap.style.display = 'none';
}

// ---------- Friendly error mapping ----------

function friendlyError(e) {
  if (!e) return 'Unknown error';
  // AES-GCM auth failures surface as generic OperationError
  if (e.name === 'OperationError' || /operation failed/i.test(String(e && e.message || ''))) {
    return 'Wrong password or corrupted file.';
  }
  return (e && e.message) ? e.message : String(e);
}

// ---------- Round-trip verification ----------

async function verifyRoundTrip(containerBuf, password, expectedPlain) {
  const pt = await decryptBytes(containerBuf, password);
  const got = new Uint8Array(pt);
  const exp = new Uint8Array(expectedPlain);
  if (got.byteLength !== exp.byteLength) return false;
  for (let i = 0; i < got.byteLength; i++) if (got[i] !== exp[i]) return false;
  return true;
}

// ---------- Password generator + strength ----------

const PASSWORD_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.?';

function generatePassword(length = 24) {
  const buf = new Uint32Array(length);
  crypto.getRandomValues(buf);
  let pw = '';
  for (let i = 0; i < length; i++) pw += PASSWORD_CHARS[buf[i] % PASSWORD_CHARS.length];
  // ensure at least one of each class
  if (!/[A-Z]/.test(pw)) pw = 'A' + pw.slice(1);
  if (!/[a-z]/.test(pw)) pw = 'a' + pw.slice(1);
  if (!/[0-9]/.test(pw)) pw = '1' + pw.slice(1);
  if (!/[^A-Za-z0-9]/.test(pw)) pw = '!' + pw.slice(1);
  return pw;
}

function strengthOf(pw) {
  if (!pw) return 0;
  let classes = 0;
  if (/[a-z]/.test(pw)) classes++;
  if (/[A-Z]/.test(pw)) classes++;
  if (/[0-9]/.test(pw)) classes++;
  if (/[^A-Za-z0-9]/.test(pw)) classes++;
  const bits = pw.length * Math.log2(classes || 1);
  // Scale aligned with the 24-char generator output (48 bits ≈ Strong);
  // previously the meter could never rate its own generated passwords.
  if (bits < 28) return 1;
  if (bits < 40) return 2;
  if (bits < 48) return 3;
  return 4;
}

const STRENGTH_LABELS = {0:'—',1:'Weak',2:'Fair',3:'Good',4:'Strong'};

function updateStrength() {
  const s = strengthOf(UI.password.value);
  UI.strengthFill.style.width = (s * 25) + '%';
  UI.strengthFill.setAttribute('data-level', String(s));
  UI.strengthLabel.textContent = STRENGTH_LABELS[s];
}

UI.genPassBtn.addEventListener('click', ()=>{
  UI.password.value = generatePassword();
  updateStrength();
  UI.password.focus();
  logStatus('Generated a random strong password (' + UI.password.value.length + ' chars).');
});

UI.password.addEventListener('input', updateStrength);
updateStrength();

async function encryptBytes(plainBytes, password) {
  const salt = randBytes(16);
  const key = await deriveKey(password, salt);
  const iv = randBytes(12);
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv:iv}, key, plainBytes);
  const magic = new TextEncoder().encode('BLKOUT01');
  const out = new Uint8Array(magic.byteLength + salt.length + iv.length + ct.byteLength);
  let off=0;
  out.set(magic, off); off+=magic.byteLength;
  out.set(salt, off); off+=salt.length;
  out.set(iv, off); off+=iv.length;
  out.set(new Uint8Array(ct), off);
  return out.buffer;
}

async function decryptBytes(containerBuf, password) {
  const container = new Uint8Array(containerBuf);
  const magic = new TextEncoder().encode('BLKOUT01');
  if (container.length < magic.length + 16 + 12) throw new Error('container too small');
  for (let i=0;i<magic.length;i++) if (container[i] !== magic[i]) throw new Error('invalid magic header');
  let off = magic.length;
  const salt = container.slice(off, off+16); off+=16;
  const iv = container.slice(off, off+12); off+=12;
  const ct = container.slice(off);
  const key = await deriveKey(password, salt);
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:iv}, key, ct);
  return pt;
}

// Data Compression via Web Streams
async function compressBytes(bytes) {
  const stream = new Blob([bytes]).stream();
  const compressedStream = stream.pipeThrough(new CompressionStream('gzip'));
  const response = new Response(compressedStream);
  return new Uint8Array(await response.arrayBuffer());
}

async function decompressBytes(bytes) {
  const stream = new Blob([bytes]).stream();
  const decompressedStream = stream.pipeThrough(new DecompressionStream('gzip'));
  const response = new Response(decompressedStream);
  return new Uint8Array(await response.arrayBuffer());
}

// Build plaintext with metadata (name, type, size) + Compression
async function buildPlainWithBytes(bytes, name, type) {
  const compressedAb = await compressBytes(bytes);

  const meta = {
    name: name || 'output.bin',
    type: type || 'application/octet-stream',
    size: bytes.byteLength,
    compressed: true,
    compression: 'gzip',
    createdAt: (new Date()).toISOString()
  };
  const metaStr = JSON.stringify(meta);
  const metaBytes = new TextEncoder().encode(metaStr);
  const header = writeU32(metaBytes.length);
  const out = new Uint8Array(4 + metaBytes.length + compressedAb.byteLength);
  let p=0;
  out.set(header, p); p+=4;
  out.set(metaBytes, p); p+=metaBytes.length;
  out.set(compressedAb, p);
  return out.buffer;
}

async function buildPlainWithMetadata(file) {
  const ab = await fileToArrayBuffer(file);
  return buildPlainWithBytes(new Uint8Array(ab), file.name, file.type);
}

// Parse Plaintext
async function parsePlainWithMetadata(plainBuf) {
  const bytes = new Uint8Array(plainBuf);
  if (bytes.length < 4) throw new Error('plaintext too small for metadata');
  const metaLen = readU32(bytes, 0);
  if (metaLen < 0 || metaLen > bytes.length - 4) throw new Error('invalid metadata length');
  const metaBytes = bytes.slice(4, 4+metaLen);
  const metaStr = new TextDecoder().decode(metaBytes);
  let meta = {};
  try { meta = JSON.parse(metaStr); } catch (e) { meta = {name:'output', type:'application/octet-stream'}; }

  let fileBytes = bytes.slice(4+metaLen);

  // Apply decompression if meta states it's compressed
  if (meta.compressed && meta.compression === 'gzip') {
     fileBytes = await decompressBytes(fileBytes);
  }

  return {meta, fileBytes};
}

// PNG helpers (insert/extract chunk bLoK)
function isPng(bytes) {
  if (bytes.length < 8) return false;
  const sig = [137,80,78,71,13,10,26,10];
  for (let i=0;i<8;i++) if (bytes[i] !== sig[i]) return false;
  return true;
}

function insertPngCamo(pngBytes, payloadBytes) {
  if (!isPng(pngBytes)) throw new Error('not a PNG');
  let off = 8;
  while (off + 8 <= pngBytes.length) {
    const len = readU32(pngBytes, off);
    const type = String.fromCharCode(...pngBytes.slice(off+4, off+8));
    const next = off + 8 + len + 4;
    if (next > pngBytes.length) throw new Error('malformed PNG');
    if (type === 'IEND') {
      const typeBytes = new TextEncoder().encode('bLoK');
      const lenBytes = writeU32(payloadBytes.length);
      const crcInput = new Uint8Array(typeBytes.length + payloadBytes.length);
      crcInput.set(typeBytes,0); crcInput.set(payloadBytes, typeBytes.length);
      const crc = crc32(crcInput);
      const crcBytes = writeU32(crc);
      const head = pngBytes.slice(0, off);
      const tail = pngBytes.slice(off);
      const newBytes = new Uint8Array(head.length + 4 + 4 + payloadBytes.length + 4 + tail.length);
      let p=0;
      newBytes.set(head, p); p+=head.length;
      newBytes.set(lenBytes, p); p+=4;
      newBytes.set(typeBytes, p); p+=4;
      newBytes.set(payloadBytes, p); p+=payloadBytes.length;
      newBytes.set(crcBytes, p); p+=4;
      newBytes.set(tail, p);
      return newBytes;
    }
    off = next;
  }
  throw new Error('IEND not found');
}

function extractPngCamo(pngBytes) {
  if (!isPng(pngBytes)) throw new Error('not a PNG');
  let off=8;
  while (off + 8 <= pngBytes.length) {
    const len = readU32(pngBytes, off);
    const type = String.fromCharCode(...pngBytes.slice(off+4, off+8));
    const dataStart = off+8;
    const next = dataStart + len + 4;
    if (next > pngBytes.length) throw new Error('malformed PNG');
    if (type === 'bLoK') {
      return pngBytes.slice(dataStart, dataStart+len);
    }
    off = next;
  }
  throw new Error('no camo chunk found');
}

// CRC32 (IEEE)
function crc32(buf) {
  let table = crc32.table;
  if (!table) {
    table = new Uint32Array(256);
    for (let i=0;i<256;i++) {
      let c=i;
      for (let k=0;k<8;k++) c = (c & 1) ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
      table[i]=c>>>0;
    }
    crc32.table = table;
  }
  let crc = 0xFFFFFFFF;
  for (let i=0;i<buf.length;i++) {
    crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xFF];
  }
  return (~crc) >>> 0;
}

function fileToArrayBuffer(file) {
  if (file && typeof file.arrayBuffer === 'function') {
    return file.arrayBuffer();
  }
  return new Promise((res, rej)=>{
    const r = new FileReader();
    r.onload = ()=> res(r.result);
    r.onerror = ()=> rej(r.error);
    r.readAsArrayBuffer(file);
  });
}

function saveAsFile(buf, filename, mimeType) {
  filename = sanitizeFileName(filename);
  if (UI._artifactUrl) { URL.revokeObjectURL(UI._artifactUrl); }
  const blob = new Blob([buf], {type: mimeType || 'application/octet-stream'});
  const url = URL.createObjectURL(blob);
  UI._artifactUrl = url;
  UI._currentArtifact = { buffer: buf, filename: filename, mimeType: mimeType || 'application/octet-stream' };
  UI.downloadBtn.style.display='inline-block';
  if (UI.saveCloudBtn) UI.saveCloudBtn.style.display='inline-block';
  UI.downloadBtn.onclick = ()=> {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
  };
  logToConsole(filename + ' (ready to export / save to cloud)');
}

// black PNG generator for cover
function makeBlackPngBlob(w=1024, h=1024) {
  const c = document.createElement('canvas');
  c.width = w; c.height = h;
  const ctx = c.getContext('2d');
  ctx.fillStyle = '#000000';
  ctx.fillRect(0,0,w,h);
  return new Promise((res) => c.toBlob(b=>res(b), 'image/png'));
}

function setFileInputFromBlob(inputEl, blob, filename) {
  const f = new File([blob], filename, {type: 'image/png', lastModified: Date.now()});
  const dt = new DataTransfer();
  dt.items.add(f);
  inputEl.files = dt.files;
}

// ---------- File info display ----------

function formatBytes(n) {
  if (!Number.isFinite(n) || n < 0) return '0 B';
  const units = ['B','KB','MB','GB','TB'];
  let v = n, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed((i === 0 || v >= 10) ? 0 : 1) + ' ' + units[i];
}

function updateFileInfo(inputEl, infoEl) {
  const f = inputEl.files && inputEl.files[0];
  if (!f) { infoEl.textContent = ''; infoEl.style.display = 'none'; return; }
  infoEl.textContent = f.name + ' — ' + formatBytes(f.size);
  infoEl.style.display = 'block';
}

UI.fileIn.addEventListener('change', ()=> {
  updateFileInfo(UI.fileIn, UI.fileInfo);
  autoSuggestMode(UI.fileIn.files[0]);
});
UI.coverIn.addEventListener('change', ()=> updateFileInfo(UI.coverIn, UI.coverInfo));

// ---------- Auto mode suggestion ----------

async function autoSuggestMode(file) {
  if (!file) return;
  const name = file.name.toLowerCase();
  const currentMode = UI.mode.value;

  if ((currentMode === 'encrypt' || currentMode === 'text-encrypt') && name.endsWith('.blackout')) {
    UI.mode.value = 'decrypt';
    toggleCoverUI();
    logToConsole('Auto-suggested Decrypt mode — input looks like a .blackout container.', 'data');
    return;
  }

  // Only suggest decrypt for a PNG if it actually carries an embedded payload,
  // so a regular PNG that the user wants to ENCRYPT is never mis-routed.
  if ((currentMode === 'encrypt' || currentMode === 'encrypt-raw') && name.endsWith('.png')) {
    try {
      const bytes = new Uint8Array(await fileToArrayBuffer(file));
      if (isPng(bytes)) {
        extractPngCamo(bytes); // throws when no bLoK chunk exists
        if (UI.mode.value === currentMode) {
          UI.mode.value = 'decrypt';
          toggleCoverUI();
          logToConsole('Auto-suggested Decrypt mode — PNG contains an embedded payload.', 'data');
        }
      }
    } catch (e) { /* plain PNG — no suggestion */ }
  }
}

// ---------- Drag & drop ----------

function setupDropZone(fieldId, inputEl, infoEl, kind) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  field.addEventListener('dragover', (e)=>{ e.preventDefault(); field.classList.add('dragover'); });
  field.addEventListener('dragleave', ()=> field.classList.remove('dragover'));
  field.addEventListener('drop', (e)=>{
    e.preventDefault();
    field.classList.remove('dragover');
    const files = e.dataTransfer && e.dataTransfer.files;
    if (!files || !files.length) return;
    if (kind === 'cover' && !/\.png$/i.test(files[0].name) && files[0].type !== 'image/png') {
      logStatus('Cover image must be a PNG', true);
      return;
    }
    const dt = new DataTransfer();
    for (const f of files) dt.items.add(f);
    inputEl.files = dt.files;
    inputEl.dispatchEvent(new Event('change', {bubbles: true}));
    logStatus((kind === 'cover' ? 'Cover' : 'File') + ' loaded: ' + files[0].name);
  });
}

setupDropZone('fileDrop', UI.fileIn, UI.fileInfo, 'file');
setupDropZone('coverDrop', UI.coverIn, UI.coverInfo, 'cover');

// ---------- Password visibility toggles ----------

function setupPassToggle(btnId, inputId) {
  const btn = document.getElementById(btnId);
  const input = document.getElementById(inputId);
  if (!btn || !input) return;
  btn.dataset.showLabel = btn.getAttribute('aria-label') || 'Show password';
  btn.addEventListener('click', ()=>{
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    btn.classList.toggle('visible', show);
    btn.setAttribute('aria-pressed', String(show));
    btn.setAttribute('aria-label', show ? (btn.dataset.showLabel.indexOf('asscode') !== -1 ? 'Hide passcode' : 'Hide password') : (btn.dataset.showLabel || 'Show password'));
    input.focus();
  });
}

function resetPassToggle(btnId, inputId) {
  const b = document.getElementById(btnId);
  const i = document.getElementById(inputId);
  if (!b || !i) return;
  i.type = 'password';
  b.classList.remove('visible');
  b.setAttribute('aria-pressed', 'false');
  b.setAttribute('aria-label', b.dataset.showLabel || 'Show password');
}

setupPassToggle('togglePass', 'password');
setupPassToggle('toggleSetupPass', 'setupPass');
setupPassToggle('toggleSetupPassConfirm', 'setupPassConfirm');
setupPassToggle('toggleUnlockPass', 'unlockPass');

function toggleCoverUI() {
  const mode = UI.mode.value;
  // text-encrypt shows the cover picker too so a leftover cover is never used invisibly
  const show = (mode === 'encrypt' || mode === 'camo' || mode === 'text-encrypt');
  UI.coverIn.style.display = show ? 'block' : 'none';
  UI.coverLabel.textContent = mode === 'text-encrypt'
    ? 'Cover PNG (optional — message will be embedded inside)'
    : 'Cover PNG (for camo / encrypt)';
  UI.coverLabel.style.display = show ? 'block' : 'none';
  UI.makeBlackCover.style.display = show ? 'inline-block' : 'none';
  UI.useDemoCover.style.display = show ? 'inline-block' : 'none';
  if (UI.coverDrop) UI.coverDrop.style.display = show ? 'block' : 'none';
  // text modes reveal the message box
  const isTextMode = (mode === 'text-encrypt' || mode === 'text-decrypt');
  UI.textWrap.style.display = isTextMode ? 'block' : 'none';
  if (isTextMode) {
    UI.textLabel.textContent = mode === 'text-encrypt'
      ? 'Message to Encrypt (text mode)'
      : 'Decrypted Message (read-only output) — shown here';
    if (mode === 'text-decrypt') UI.textInput.readOnly = true; else UI.textInput.readOnly = false;
  }
}
UI.mode.addEventListener('change', toggleCoverUI);
toggleCoverUI();

UI.copyMsgBtn.addEventListener('click', async ()=> {
  const text = UI.textInput.value;
  if (!text) { logStatus('Nothing to copy yet.', true); return; }
  try {
    await navigator.clipboard.writeText(text);
    logStatus('Message copied to clipboard.');
  } catch (e) {
    UI.textInput.select();
    logStatus('Clipboard blocked — message selected, press Ctrl/Cmd+C to copy.');
  }
});

UI.clearTextBtn.addEventListener('click', ()=> {
  UI.textInput.value = '';
  UI.textInput.focus();
});

// Pressing Enter on the password or output-name fields runs the protocol
[UI.password, UI.outputName].forEach(el => {
  el.addEventListener('keydown', (e) => { if (e.key === 'Enter') UI.goBtn.click(); });
});

UI.makeBlackCover.addEventListener('click', async ()=> {
  try {
    const blob = await makeBlackPngBlob(1024,1024);
    setFileInputFromBlob(UI.coverIn, blob, 'black_cover.png');
    updateFileInfo(UI.coverIn, UI.coverInfo);
    logStatus('Black cover generated and selected.');
  } catch (e) { logStatus('Error generating black PNG: '+e.message, true); }
});

UI.useDemoCover.addEventListener('click', async ()=> {
  const c = document.createElement('canvas'); c.width=512; c.height=512;
  const ctx = c.getContext('2d');
  ctx.fillStyle='#071019'; ctx.fillRect(0,0,512,512);
  ctx.fillStyle='#00ff88'; ctx.fillRect(40,40,432,432);
  c.toBlob(b=> {
    setFileInputFromBlob(UI.coverIn, b, 'demo_cover.png');
    updateFileInfo(UI.coverIn, UI.coverInfo);
    logStatus('Demo cover selected.');
  }, 'image/png');
});

// ---------- Main actions ----------

UI.goBtn.addEventListener('click', async ()=> {
  hideStatus();
  const probs = supportProblems();
  if (probs.length) { logStatus(probs.join(' '), true); return; }

  const file = UI.fileIn.files[0];
  const pass = UI.password.value;
  const mode = UI.mode.value;
  try {
    if ((mode === 'encrypt' || mode === 'encrypt-raw' || mode === 'camo' || mode === 'decrypt' || mode === 'decamo' || mode === 'text-decrypt') && !file) { logStatus('Select an input file first', true); return; }
    // camo only embeds an already-encrypted container — no password needed there
    if ((mode==='encrypt' || mode==='encrypt-raw' || mode==='decrypt' || mode==='text-encrypt' || mode==='text-decrypt') && (!pass)) { logStatus('Provide a password', true); return; }

    UI.goBtn.textContent = 'Processing...';
    UI.goBtn.disabled = true;
    UI.goBtn.setAttribute('aria-busy', 'true');

    // Drop any previous artifact so a stale download can never be triggered
    if (UI._artifactUrl) { URL.revokeObjectURL(UI._artifactUrl); UI._artifactUrl = null; }
    UI.downloadBtn.style.display = 'none';

    if (file && file.size > 150 * 1024 * 1024) {
      logToConsole('Note: large input (' + formatBytes(file.size) + ') — processing is memory-heavy in the browser.', 'data');
    }

    if (mode === 'encrypt-raw') {
      setProgress('Compressing & building container…', 8);
      const plain = await buildPlainWithMetadata(file);
      setProgress('Deriving key & encrypting…', 40);
      const container = await encryptBytes(plain, pass);
      setProgress('Verifying round-trip…', 75);
      if (!(await verifyRoundTrip(container, pass, plain))) throw new Error('round-trip verification failed');
      setProgress('Ready to download…', 100);
      saveAsFile(container, customOrDefault(UI.outputName.value, file.name + '.blackout', '.blackout'), 'application/octet-stream');
      logStatus('Encrypted raw container ready (.blackout) (Compressed) — round-trip verified');
    }

    else if (mode === 'encrypt') {
      setProgress('Compressing & building container…', 6);
      const plain = await buildPlainWithMetadata(file);
      setProgress('Deriving key & encrypting…', 35);
      const container = await encryptBytes(plain, pass);
      setProgress('Verifying round-trip…', 60);
      if (!(await verifyRoundTrip(container, pass, plain))) throw new Error('round-trip verification failed');
      let coverFile = UI.coverIn.files[0];
      if (!coverFile) {
        const blob = await makeBlackPngBlob(1024,1024);
        coverFile = new File([blob], stripExt(file.name || 'cover') + '.png', {type:'image/png'});
      }
      setProgress('Embedding into cover PNG…', 80);
      const pngAb = await fileToArrayBuffer(coverFile);
      const out = insertPngCamo(new Uint8Array(pngAb), new Uint8Array(container));
      const outName = customOrDefault(UI.outputName.value, coverFile.name, '.png');
      setProgress('Ready to download…', 100);
      saveAsFile(out.buffer, outName, 'image/png');
      logStatus('Compressed, encrypted, and embedded into PNG. Saved as ' + outName + ' (round-trip verified)');
    }

    else if (mode === 'camo') {
      const inputAb = await fileToArrayBuffer(file);
      const magic = new TextEncoder().encode('BLKOUT01');
      const startsWithMagic = (inputAb.byteLength >= magic.byteLength && (() => {
        const arr = new Uint8Array(inputAb, 0, magic.byteLength); for(let i=0;i<magic.byteLength;i++) if(arr[i]!==magic[i]) return false; return true;
      })());
      if (!startsWithMagic) { logStatus('Input does not look like a .blackout container. Use Encrypt mode to create one.', true); return; }
      let coverFile = UI.coverIn.files[0];
      if (!coverFile) {
        const blob = await makeBlackPngBlob(1024,1024);
        coverFile = new File([blob], 'black_cover.png', {type:'image/png'});
      }
      setProgress('Embedding into cover PNG…', 30);
      const pngAb = await fileToArrayBuffer(coverFile);
      const out = insertPngCamo(new Uint8Array(pngAb), new Uint8Array(inputAb));
      const outName = customOrDefault(UI.outputName.value, coverFile.name.replace(/\.png$/i, '') + '.camo.png');
      setProgress('Ready to download…', 100);
      saveAsFile(out.buffer, outName, 'image/png');
      logStatus('Embedded existing container into PNG. Saved as ' + outName);
    }

    else if (mode === 'decrypt') {
      const ab = await fileToArrayBuffer(file);
      let containerBuf = ab;
      if (isPng(new Uint8Array(ab))) {
        try {
          setProgress('Extracting embedded payload…', 10);
          const payload = extractPngCamo(new Uint8Array(ab));
          containerBuf = payload.buffer;
        } catch (e) {
          logStatus('PNG selected, but no embedded payload (bLoK chunk) was found.', true);
          return;
        }
      }
      setProgress('Decrypting & decompressing…', 55);
      const pt = await decryptBytes(containerBuf, pass);
      const parsed = await parsePlainWithMetadata(pt);
      setProgress('Preparing download…', 90);
      const suggested = sanitizeFileName(UI.outputName.value.trim() || (parsed.meta && parsed.meta.name) || 'decrypted.bin');
      saveAsFile(parsed.fileBytes.buffer, suggested, parsed.meta.type || 'application/octet-stream');
      logStatus('Decrypted and decompressed — ready to download as ' + suggested);
    }

    else if (mode === 'decamo') {
      setProgress('Extracting camo payload…', 20);
      const pngAb = await fileToArrayBuffer(file);
      const payload = extractPngCamo(new Uint8Array(pngAb));
      setProgress('Ready to download…', 100);
      saveAsFile(payload.buffer, customOrDefault(UI.outputName.value, 'extracted-' + file.name + '.blackout', '.blackout'), 'application/octet-stream');
      logStatus('Extracted payload saved as raw .blackout. Use Decrypt mode to restore file.');
    }

    else if (mode === 'text-encrypt') {
      const text = UI.textInput.value;
      if (!text) { logStatus('Enter a message to encrypt first', true); return; }
      setProgress('Compressing message…', 10);
      const plain = await buildPlainWithBytes(new TextEncoder().encode(text), 'message.txt', 'text/plain');
      setProgress('Deriving key & encrypting…', 40);
      const container = await encryptBytes(plain, pass);
      setProgress('Verifying round-trip…', 75);
      if (!(await verifyRoundTrip(container, pass, plain))) throw new Error('round-trip verification failed');
      let coverFile = UI.coverIn.files[0];
      if (coverFile) {
        setProgress('Embedding into cover PNG…', 85);
        const pngAb = await fileToArrayBuffer(coverFile);
        const out = insertPngCamo(new Uint8Array(pngAb), new Uint8Array(container));
        const outName = customOrDefault(UI.outputName.value, coverFile.name, '.png');
        setProgress('Ready to download…', 100);
        saveAsFile(out.buffer, outName, 'image/png');
        logStatus('Message encrypted & embedded into PNG. Saved as ' + outName + ' (round-trip verified)');
      } else {
        const outName = customOrDefault(UI.outputName.value, 'message.txt.blackout', '.blackout');
        setProgress('Ready to download…', 100);
        saveAsFile(container, outName, 'application/octet-stream');
        logStatus('Message encrypted into ' + outName + ' (round-trip verified)');
      }
    }

    else if (mode === 'text-decrypt') {
      const ab = await fileToArrayBuffer(file);
      let containerBuf = ab;
      if (isPng(new Uint8Array(ab))) {
        try {
          setProgress('Extracting embedded payload…', 10);
          const payload = extractPngCamo(new Uint8Array(ab));
          containerBuf = payload.buffer;
        } catch (e) {
          logStatus('PNG selected, but no embedded payload (bLoK chunk) was found.', true);
          return;
        }
      }
      setProgress('Decrypting & decompressing…', 55);
      const pt = await decryptBytes(containerBuf, pass);
      const parsed = await parsePlainWithMetadata(pt);
      const text = new TextDecoder().decode(parsed.fileBytes);
      UI.textInput.value = text;
      UI.textInput.readOnly = true;
      logStatus('Message decrypted and shown in the text box above. Download also ready (' + formatBytes(parsed.fileBytes.byteLength) + ').');
      const suggested = sanitizeFileName(UI.outputName.value.trim() || (parsed.meta && parsed.meta.name) || 'message.txt');
      saveAsFile(parsed.fileBytes.buffer, suggested, parsed.meta.type || 'text/plain');
    }

  } catch (e) {
    logStatus('Error: ' + friendlyError(e), true);
    console.error(e);
  } finally {
    UI.goBtn.textContent = GO_LABEL;
    UI.goBtn.disabled = false;
    UI.goBtn.setAttribute('aria-busy', 'false');
    endProgress();
  }
});

// nested re-encrypt
UI.reencryptBtn.addEventListener('click', async ()=> {
  const file = UI.fileIn.files[0];
  const pass = UI.password.value;
  if (!file || !pass) { logStatus('Provide .blackout file and new password', true); return; }
  try {
    UI.downloadBtn.style.display = 'none';
    const ab = await fileToArrayBuffer(file);
    const wrapped = await encryptBytes(ab, pass);
    saveAsFile(wrapped, file.name + '.reencrypted.blackout', 'application/octet-stream');
    logStatus('Re-encrypted nested container ready');
  } catch (e) {
    logStatus('Error: '+friendlyError(e), true);
  }
});

// inspect PNG chunks
UI.inspectBtn.addEventListener('click', async ()=> {
  const f = UI.fileIn.files[0];
  if (!f) { logStatus('Select a PNG to inspect', true); return; }
  try {
    const ab = await fileToArrayBuffer(f);
    if (!isPng(new Uint8Array(ab))) { logStatus('Not a PNG', true); return; }
    const chunks = [];
    let off=8;
    const bytes = new Uint8Array(ab);
    while (off+8 <= bytes.length) {
      const len = readU32(bytes, off);
      const type = String.fromCharCode(...bytes.slice(off+4, off+8));
      const dataStart = off+8;
      const next = dataStart + len + 4;
      chunks.push({type, len});
      off = next;
    }
    logToConsole(JSON.stringify(chunks, null, 2), 'data');
    UI.downloadBtn.style.display='none';
    hideStatus();
  } catch (e) {
    logStatus('Error: '+friendlyError(e), true);
  }
});

// meta inspect (requires password)
UI.metaInspectBtn.addEventListener('click', async ()=> {
  const f = UI.fileIn.files[0];
  if (!f) { logStatus('Select a .blackout or camo PNG to inspect', true); return; }
  if (!UI.password.value) { logStatus('Provide password to inspect metadata', true); return; }
  try {
    const ab = await fileToArrayBuffer(f);
    let containerBuf = ab;
    if (isPng(new Uint8Array(ab))) {
      try { const payload = extractPngCamo(new Uint8Array(ab)); containerBuf = payload.buffer; } catch(e){}
    }
    const pt = await decryptBytes(containerBuf, UI.password.value);
    const parsed = await parsePlainWithMetadata(pt);
    logToConsole('metadata: ' + JSON.stringify(parsed.meta, null, 2), 'data');
    UI.downloadBtn.style.display='none';
    hideStatus();
  } catch (e) {
    logStatus('Error reading metadata: '+friendlyError(e), true);
  }
});

UI.clearBtn.addEventListener('click', ()=> {
  if (!confirm('Clear the current inputs, password and console output?')) return;
  UI.fileIn.value=''; UI.coverIn.value=''; UI.password.value=''; UI.outputName.value=''; UI.textInput.value='';
  updateFileInfo(UI.fileIn, UI.fileInfo);
  updateFileInfo(UI.coverIn, UI.coverInfo);
  clearConsole();
  updateStrength();
  UI.downloadBtn.style.display='none';
  if (UI._artifactUrl) { URL.revokeObjectURL(UI._artifactUrl); UI._artifactUrl = null; }
  resetPassToggle('togglePass', 'password');
  resetPassToggle('toggleSetupPass', 'setupPass');
  resetPassToggle('toggleSetupPassConfirm', 'setupPassConfirm');
  resetPassToggle('toggleUnlockPass', 'unlockPass');
  resetPassToggle('toggleRecoverNewPass', 'recoverNewPass');
  resetPassToggle('toggleRecoverNewPassConfirm', 'recoverNewPassConfirm');
  hideStatus();
});

/* Lock overlay Logic With Persistent Hashing */
const lockEl = document.getElementById('lock');
const appEl = document.getElementById('app');
const setupMode = document.getElementById('setupMode');
const unlockMode = document.getElementById('unlockMode');
const insecureMode = document.getElementById('insecureMode');
const insecureOriginEl = document.getElementById('insecureOrigin');
const insecureBypassBtn = document.getElementById('insecureBypassBtn');

const setupPass = document.getElementById('setupPass');
const setupPassConfirm = document.getElementById('setupPassConfirm');
const setPassBtn = document.getElementById('setPassBtn');
const setupError = document.getElementById('setupError');

const unlockPass = document.getElementById('unlockPass');
const unlockBtn = document.getElementById('unlockBtn');
const forgotBtn = document.getElementById('forgotBtn');
const unlockError = document.getElementById('unlockError');

const deviceResetBtn = document.getElementById('deviceResetBtn');

// Keep the app background inert (not focusable) while the lock is up.
// NOTE: aria-hidden="true" HIDES the overlay (see CSS), so locked === overlay visible.
function setLocked(locked) {
  lockEl.setAttribute('aria-hidden', String(!locked));
  if ('inert' in appEl) appEl.inert = locked;
  if (!locked) {
    // move focus into the app now that the overlay is gone
    setTimeout(()=> { (UI.fileIn || appEl).focus && (UI.fileIn || appEl).focus(); }, 0);
  }
}

// Helper to hash passcode for local storage
// v2: PBKDF2-SHA-256 (150k iterations) with random 16-byte salt, stored as JSON.
// Legacy (pre-v2): plain SHA-256 hex digest — verified and migrated to v2 on unlock.
const LOCK_STORAGE_KEY = 'blackout_app_lock';
const LOCK_ITERATIONS = 150000;

async function hashPasscode(pass) {
  const msgBuffer = new TextEncoder().encode(pass);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function deriveLockKey(pass, saltHex) {
  const pwKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: LOCK_ITERATIONS, hash: 'SHA-256' },
    pwKey, 256
  );
}

async function createLockRecord(pass) {
  const saltHex = bytesToHex(randBytes(16));
  const bits = await deriveLockKey(pass, saltHex);
  return JSON.stringify({ v: 2, salt: saltHex, hash: bytesToHex(bits) });
}

function isLegacyLock(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value);
}

// Shared check for JSON hashed records of the form {v, salt, hash}.
async function verifyHashedRecord(record, secret, expectedV) {
  try {
    const rec = JSON.parse(record);
    if (!rec || !rec.salt || !rec.hash) return false;
    if (expectedV !== undefined && rec.v !== expectedV) return false;
    const bits = await deriveLockKey(secret, rec.salt);
    return bytesToHex(bits) === rec.hash;
  } catch (e) {
    return false;
  }
}

async function verifyLockRecord(record, pass) {
  if (isLegacyLock(record)) {
    return (await hashPasscode(pass)) === record;
  }
  return verifyHashedRecord(record, pass, 2);
}

// ---------- Offline recovery phrase ----------

// Curated lowercase wordlist used to mint recovery phrases.
// 8 random words from this pool ≈ 80 bits of entropy.
const RECOVERY_WORDS = [
  'able','acid','acorn','actor','agent','alarm','album','alert',
  'alien','alloy','amber','angle','ankle','apple','apron','arrow',
  'atlas','atom','audio','autumn','avenue','bacon','badge','bagel',
  'baker','bamboo','banjo','banner','basil','basin','batch','beaker',
  'beacon','beaver','beetle','bench','berry','birch','bishop','blade',
  'blanket','bluff','bolt','bonus','book','booth','bottle','boulder',
  'breeze','brick','bride','bridge','bronze','broom','brush','bubble',
  'buckle','budget','bugle','bumper','bundle','bunker','burger','butter',
  'button','buzz','cabin','cable','cactus','calf','camel','camera',
  'candle','canoe','canyon','cape','carbon','cargo','carpet','carrot',
  'castle','celery','cement','chair','chalk','charm','chart','cheese',
  'cherry','chest','chili','chime','chimney','choir','chorus','chrome',
  'chunk','cider','cinema','circle','circus','civic','cliff','climate',
  'cloak','clock','cloth','cloud','clover','coach','coast','cobra',
  'cocoon','coil','coin','collar','column','comet','comic','compass',
  'cone','copper','coral','corgi','cork','cosmos','cotton','couch',
  'coupon','crab','cradle','crane','crater','crayon','cream','credit',
  'cricket','crisp','crown','cruise','crust','crystal','cube','cucumber',
  'curtain','cushion','cycle','cyclone','dagger','dairy','daisy','dancer',
  'dart','dawn','decade','deck','deer','delta','denim','desert',
  'desk','diamond','dice','diesel','digger','digital','dime','diver',
  'dock','dodge','doll','dolphin','dome','donkey','donut','door',
  'dove','dozen','dragon','drama','dream','drift','drill','drum',
  'dryer','duck','dusk','dwarf','dynamo','eagle','earth','echo',
  'eclipse','editor','elder','email','ember','enamel','engine','equator',
  'eraser','escape','essay','ether','expert','extra','fabric','falcon',
  'fancy','farm','faucet','feast','feather','fence','fern','ferry',
  'fiber','fiddle','field','figure','filter','finch','finger','fire',
  'fjord','flame','flash','flax','flint','float','flock','flood',
  'flour','flower','flute','foam','foil','folder','folk','forest',
  'forge','fossil','fountain','fox','frame','freeze','frost','fruit',
  'fuel','funnel','fur','fuse','galaxy','garden','garlic','gate',
  'gauge','gazelle','gecko','geyser','giant','ginger','giraffe','glacier',
  'glass','globe','glove','glow','glue','gnome','goal','goat',
  'gold','goose','gopher','gospel','grain','grape','graph','grass',
  'gravel','gravity','green','grill','groove','ground','grove','guard',
  'guitar','gull','gum','gust','gutter','gym','hail','hammer',
  'harbor','harp','hatch','hawk','hay','hazel','hearth','hedge',
  'helmet','herb','herd','heron','hexagon','hike','hill','hinge',
  'hippo','hive','hockey','hollow','honey','hoof','hook','horizon',
  'horn','horse','hose','hotel','house','hover','hub','hum',
  'humid','humor','hutch','hyena','hymn','ice','iceberg','icicle',
  'icon','igloo','image','inch','income','index','ink','input',
  'iris','iron','island','isle','ivory','ivy','jacket','jaguar',
  'jam','jar','jazz','jelly','jester','jet','jewel','jigsaw',
  'jingle','joker','jolt','journal','journey','jug','jungle','junk',
  'jury','kayak','kettle','key','kick','kiln','kite','kitten',
  'kiwi','knight','knot','koala','ladder','lady','lake','lamb',
  'lamp','lance','lantern','laptop','lark','laser','latch','lava',
  'lawn','layer','leaf','league','ledge','lemon','lens','leopard',
  'letter','lettuce','lever','lift','light','lilac','lily','lime',
  'linen','liner','link','lion','lizard','llama','loaf','lobby',
  'locker','locust','lodge','logic','loop','lotus','lounge','lumber',
  'lunar','lunch','lynx','machine','magic','magnet','maiden','mail',
  'major','maker','mango','mantle','maple','marble','march','marker',
  'marsh','mask','mast','math','matrix','maze','meadow','medal',
  'melody','melon','memo','mentor','menu','metal','meteor','meter',
  'metro','micro','mile','milk','mill','mint','mirror','mist',
  'moat','model','modem','module','monarch','monkey','month','moon',
  'moose','mosaic','moss','motel','moth','motor','mound','mount',
  'mouse','mouth','muffin','mule','mural','museum','mushroom','music',
  'mustang','myth','nail','napkin','nectar','needle','nephew','nest',
  'nickel','night','ninja','noble','noise','noodle','north','notch',
  'nugget','nurse','nut','nylon','oasis','ocean','octave','octopus',
  'office','olive','omelet','onion','opera','orbit','orchid','order',
  'organ','origin','osprey','ostrich','otter','oven','owl','oxygen',
  'oyster','paddle','paint','palm','pancake','panda','panel','pantry',
  'paper','parade','parcel','park','parrot','parsley','pasta','paste',
  'pasture','patio','pause','peach','peacock','peak','peanut','pearl',
  'pebble','pedal','pelican','pencil','penguin','pepper','perch','petal',
  'petrol','phone','photo','piano','picnic','pie','pier','pigeon',
  'pig','pike','pillow','pilot','pine','pink','pint','pioneer',
  'pipe','pirate','piston','pizza','planet','plank','plant','plaza',
  'plow','plug','plum','plume','pocket','poem','point','polar',
  'pole','pond','pony','pool','popcorn','poppy','porch','porter',
  'post','pot','potato','pouch','powder','power','prawn','prism',
  'prize','probe','prune','pub','puddle','pulse','pump','punch',
  'puppet','puppy','purse','puzzle','pyramid','quail','quake','quartz',
  'queen','quest','queue','quill','quilt','quiver','quote','rabbit',
  'raccoon','radar','radio','raft','rail','rain','rally','ranch',
  'ranger','raspberry','rat','raven','ray','razor','reactor','reader',
  'recipe','record','reef','reel','reflex','relay','relic','remix',
  'report','resort','rhino','rhythm','ribbon','rice','ridge','rifle',
  'ring','ripple','river','road','roast','robin','robot','rocket',
  'rod','roll','roof','room','rooster','root','rope','rose',
  'rover','royal','rubber','rubble','ruby','ruler','runner','rust',
  'saddle','safari','safe','sage','sail','salad','salmon','salon',
  'salt','sample','sand','sapling','satin','sauce','sauna','scale',
  'scarf','scent','school','scoop','scope','score','scout','screen',
  'screw','scrub','seal','search','season','seed','sensor','series',
  'sesame','settle','shadow','shaft','shark','shed','sheep','sheet',
  'shelf','shell','shield','shift','shine','ship','shirt','shock',
  'shoe','shore','shovel','shrub','shuffle','sight','sign','silk',
  'silver','singer','sink','siren','sister','sketch','ski','skill',
  'skin','skull','skunk','sky','slate','sleigh','slice','slide',
  'slime','slope','snail','snake','sneeze','snow','soap','sock',
  'sofa','solar','solo','sonar','song','soot','sort','sound',
  'soup','south','space','spade','spark','spear','spell','spice',
  'spike','spine','spiral','splash','sponge','spoon','sport','spot',
  'spray','spring','sprout','spruce','square','squid','squirrel','stack',
  'stage','stain','stair','stall','stamp','star','statue','steak',
  'steam','steel','steep','stem','step','stick','sting','stitch',
  'stone','stool','storm','story','stove','strand','straw','stream',
  'street','stretch','stride','strike','string','strip','stroke','strong',
  'studio','study','stump','style','suburb','sugar','suit','summit',
  'sun','super','surf','surge','survey','swallow','swamp','swan',
  'swarm','sweat','sweater','sweep','sweet','swim','swing','swirl',
  'sword','syrup','table','tablet','tackle','tail','tale','tank',
  'tap','tape','target','task','taste','taxi','tea','team',
  'teapot','temple','tennis','tent','term','test','text','theater',
  'theme','theory','thermos','thick','thief','thigh','thorn','thread',
  'thrill','throne','thunder','ticket','tide','tiger','tile','timber',
  'tin','tissue','toast','toe','toffee','token','tomato','tomb',
  'tone','tongue','tonic','tool','tooth','torch','tornado','tortoise',
  'towel','tower','town','toy','trace','track','tractor','trade',
  'trail','train','tram','trap','trash','travel','tray','tread',
  'treat','tree','trek','trench','trial','tribe','trick','trim',
  'trip','trophy','tropic','trout','truck','trumpet','trunk','trust',
  'truth','tube','tulip','tumble','tuna','tunnel','turkey','turtle',
  'tusk','tutor','twin','twist','typhoon','umbrella','uncle','uniform',
  'union','unit','unity','unlock','upper','urban','urn','usage',
  'utility','vacant','vacuum','valley','valve','van','vanilla','vapor',
  'vase','vault','vector','veil','vein','velvet','vent','verse',
  'vessel','vest','veteran','vial','vibrant','victory','video','view',
  'village','vine','vintage','vinyl','violet','violin','virus','visa',
  'vision','visit','vista','vital','vivid','vocal','volcano','volt',
  'volume','vote','voyage','waddle','wagon','waist','walk','walnut',
  'wand','warm','wasp','watch','water','wave','wax','web',
  'wedge','weed','well','west','whale','wheat','wheel','whip',
  'whisper','whistle','whole','wicked','wide','widow','wild','willow',
  'win','wind','window','wine','wing','winner','winter','wire',
  'wise','wish','witch','witness','wolf','wonder','wood','wool',
  'word','work','world','worm','worry','worship','worth','wound',
  'wrap','wreck','wrench','wrist','write','wrong','xenon','yacht',
  'yarn','yawn','year','yeast','yell','yellow','yield','yoga',
  'yolk','young','youth','zebra','zenith','zero','zest','zigzag',
  'zinc','zipper','zone','zoom'
];

function normalizePhrase(phrase) {
  return String(phrase || '').toLowerCase().trim().replace(/\s+/g, ' ');
}

function generateRecoveryPhrase(wordCount = 8) {
  const idx = new Uint32Array(wordCount);
  crypto.getRandomValues(idx);
  const n = RECOVERY_WORDS.length;
  return Array.from(idx, v => RECOVERY_WORDS[v % n]).join(' ');
}

const RECOVERY_STORAGE_KEY = 'blackout_recovery';

// Store the phrase's PBKDF2 hash (for offline verification) plus the phrase
// itself encrypted under the device passcode (so it can be re-shown from the app).
async function saveRecoveryRecord(phrase, passcode) {
  const norm = normalizePhrase(phrase);
  const saltHex = bytesToHex(randBytes(16));
  const hashBits = await deriveLockKey(norm, saltHex);
  const encSalt = randBytes(16);
  const key = await deriveKey(passcode, encSalt);
  const encIv = randBytes(12);
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv: encIv}, key, new TextEncoder().encode(norm));
  localStorage.setItem(RECOVERY_STORAGE_KEY, JSON.stringify({
    v: 1,
    salt: saltHex,
    hash: bytesToHex(hashBits),
    encSalt: bytesToHex(encSalt),
    encIv: bytesToHex(encIv),
    enc: bytesToHex(new Uint8Array(ct))
  }));
}

function getRecoveryRecord() {
  const raw = localStorage.getItem(RECOVERY_STORAGE_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}

async function verifyRecoveryPhrase(phrase) {
  const rec = getRecoveryRecord();
  if (!rec) return false;
  return verifyHashedRecord(JSON.stringify(rec), normalizePhrase(phrase), 1);
}

async function decryptRecoveryPhrase(passcode) {
  try {
    const rec = getRecoveryRecord();
    if (!rec || !rec.encSalt || !rec.encIv || !rec.enc) return null;
    const key = await deriveKey(passcode, hexToBytes(rec.encSalt));
    const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv: hexToBytes(rec.encIv)}, key, hexToBytes(rec.enc));
    return new TextDecoder().decode(pt);
  } catch (e) {
    return null;
  }
}

// Recovery UI state
let _currentPhrase = '';
const recoverPhraseOut = document.getElementById('recoverPhraseOut');
const copyPhraseBtn = document.getElementById('copyPhraseBtn');
const regenPhraseBtn = document.getElementById('regenPhraseBtn');
const recoverAck = document.getElementById('recoverAck');
const unlockPassWrap = document.getElementById('unlockPassWrap');
const recoverMode = document.getElementById('recoverMode');
const recoverPhrase = document.getElementById('recoverPhrase');
const recoverBtn = document.getElementById('recoverBtn');
const recoverBack = document.getElementById('recoverBack');
const recoverError = document.getElementById('recoverError');
const recoverFullReset = document.getElementById('recoverFullReset');
const recoverSetNew = document.getElementById('recoverSetNew');
const recoverNewPass = document.getElementById('recoverNewPass');
const recoverNewPassConfirm = document.getElementById('recoverNewPassConfirm');
const recoverNewPassError = document.getElementById('recoverNewPassError');
const recoverSetNewBtn = document.getElementById('recoverSetNewBtn');

// Mint a fresh phrase, show it, and require acknowledgement before setup can finish.
function renderRecoveryPhrase() {
  _currentPhrase = generateRecoveryPhrase();
  recoverPhraseOut.textContent = _currentPhrase;
  recoverAck.checked = false;
  setPassBtn.disabled = true;
  recoverSetNew.style.display = 'none';
  recoverNewPass.value = '';
  recoverNewPassConfirm.value = '';
}

copyPhraseBtn.addEventListener('click', async () => {
  if (!_currentPhrase) return;
  try {
    await navigator.clipboard.writeText(_currentPhrase);
  } catch (e) {
    const range = document.createRange();
    range.selectNodeContents(recoverPhraseOut);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
  const prev = copyPhraseBtn.textContent;
  copyPhraseBtn.textContent = 'Copied ✓';
  setTimeout(() => { copyPhraseBtn.textContent = prev; }, 1600);
});

regenPhraseBtn.addEventListener('click', renderRecoveryPhrase);
recoverAck.addEventListener('change', () => { setPassBtn.disabled = !recoverAck.checked; });

function initLock() {
  // ── Insecure-context guard ──────────────────────────────────────────────
  // crypto.subtle is only available in secure contexts (HTTPS or localhost).
  // On a plain-HTTP local-network URL (e.g. 192.168.x.x:5500) the API is
  // undefined, and every call to importKey / deriveBits crashes immediately.
  // Instead of showing an unusable lock form, display a clear warning and let
  // the user bypass the lock so they at least see the UI.
  if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
    if (insecureOriginEl) insecureOriginEl.textContent = window.location.host || window.location.origin;
    if (insecureMode) insecureMode.style.display = 'block';
    if (setupMode) setupMode.style.display = 'none';
    if (unlockMode) unlockMode.style.display = 'none';
    setLocked(true); // show the overlay…
    // …then wire the bypass button to dismiss it without any crypto calls
    if (insecureBypassBtn && !insecureBypassBtn._bound) {
      insecureBypassBtn._bound = true;
      insecureBypassBtn.addEventListener('click', () => setLocked(false));
    }
    return;
  }
  // ── Normal (secure-context) lock flow ──────────────────────────────────
  const saved = localStorage.getItem(LOCK_STORAGE_KEY);
  if (saved) {
    unlockMode.style.display = 'block';
    setupMode.style.display = 'none';
    unlockPass.value = '';
    // reset the recovery sub-view to its initial state
    unlockPassWrap.style.display = 'block';
    recoverMode.style.display = 'none';
    recoverSetNew.style.display = 'none';
    recoverPhrase.value = '';
    recoverNewPass.value = '';
    recoverNewPassConfirm.value = '';
    unlockPass.focus();
  } else {
    setupMode.style.display = 'block';
    unlockMode.style.display = 'none';
    setupPass.value = '';
    setupPassConfirm.value = '';
    renderRecoveryPhrase();
    setupPass.focus();
  }
  setLocked(true);
}

setPassBtn.addEventListener('click', async () => {
  setupError.style.display = 'none';
  const p1 = setupPass.value;
  const p2 = setupPassConfirm.value;

  if (!recoverAck.checked) {
    setupError.textContent = 'Please confirm you saved your recovery phrase.';
    setupError.style.display = 'block';
    return;
  }
  if (!p1) {
    setupError.textContent = 'Please enter a passcode.';
    setupError.style.display = 'block';
    return;
  }
  if (p1 !== p2) {
    setupError.textContent = 'Passcodes do not match.';
    setupError.style.display = 'block';
    return;
  }

  setPassBtn.textContent = 'Securing…';
  setPassBtn.disabled = true;
  try {
    // Persist BOTH records before unlocking: the lock record keeps reloads
    // safe, and awaiting the recovery record means the phrase shown on screen
    // is guaranteed to be stored (no silent background failure, no window
    // where Forgot? would fall back to a full reset).
    localStorage.setItem(LOCK_STORAGE_KEY, await createLockRecord(p1));
    await saveRecoveryRecord(_currentPhrase, p1);
    setLocked(false);
  } catch (e) {
    setupError.textContent = 'Error: ' + (e && e.message ? e.message : e);
    setupError.style.display = 'block';
    setPassBtn.textContent = 'Set Passcode & Enter';
    setPassBtn.disabled = false;
  }
});

unlockBtn.addEventListener('click', async () => {
  unlockError.style.display = 'none';
  const p = unlockPass.value;
  if (!p) return;

  const record = localStorage.getItem(LOCK_STORAGE_KEY);
  if (!record) { initLock(); return; }

  unlockBtn.textContent = 'Verifying…';
  unlockBtn.disabled = true;
  try {
    if (await verifyLockRecord(record, p)) {
      // migrate legacy SHA-256 records to the PBKDF2 v2 format on successful unlock
      if (isLegacyLock(record)) {
        localStorage.setItem(LOCK_STORAGE_KEY, await createLockRecord(p));
      }
      setLocked(false);
    } else {
      unlockError.textContent = 'Invalid device passcode.';
      unlockError.style.display = 'block';
    }
  } finally {
    unlockBtn.textContent = 'Decrypt Terminal';
    unlockBtn.disabled = false;
  }
});

setupPass.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') setupPassConfirm.focus();
});

setupPassConfirm.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') setPassBtn.click();
});

unlockPass.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') unlockBtn.click();
});

forgotBtn.addEventListener('click', () => {
  if (!localStorage.getItem(RECOVERY_STORAGE_KEY)) {
    // no recovery phrase stored on this device — fall back to a full reset
    const confirmReset = confirm("No recovery phrase is stored on this device. A full reset will wipe the current local device lock and any saved data associated with this browser. Continue?");
    if (confirmReset) {
      localStorage.clear();
      initLock();
    }
    return;
  }
  unlockPassWrap.style.display = 'none';
  recoverMode.style.display = 'block';
  recoverSetNew.style.display = 'none';
  recoverError.style.display = 'none';
  recoverNewPass.value = '';
  recoverNewPassConfirm.value = '';
  recoverPhrase.value = '';
  recoverPhrase.focus();
});

recoverBack.addEventListener('click', () => {
  recoverMode.style.display = 'none';
  unlockPassWrap.style.display = 'block';
  unlockPass.focus();
});

recoverBtn.addEventListener('click', async () => {
  recoverError.style.display = 'none';
  const phrase = recoverPhrase.value.trim();
  if (!phrase) {
    recoverError.textContent = 'Enter your recovery phrase.';
    recoverError.style.display = 'block';
    return;
  }
  if (!(await verifyRecoveryPhrase(phrase))) {
    recoverError.textContent = 'That recovery phrase is not valid for this device.';
    recoverError.style.display = 'block';
    return;
  }
  recoverSetNew.style.display = 'block';
  recoverNewPass.focus();
});

recoverSetNewBtn.addEventListener('click', async () => {
  recoverNewPassError.style.display = 'none';
  const p1 = recoverNewPass.value;
  const p2 = recoverNewPassConfirm.value;
  if (!p1) {
    recoverNewPassError.textContent = 'Enter a new passcode.';
    recoverNewPassError.style.display = 'block';
    return;
  }
  if (p1 !== p2) {
    recoverNewPassError.textContent = 'Passcodes do not match.';
    recoverNewPassError.style.display = 'block';
    return;
  }
  recoverSetNewBtn.textContent = 'Securing…';
  recoverSetNewBtn.disabled = true;
  try {
    // keep the same phrase, now re-encrypted under the new passcode — persist
    // before unlocking so recovery always has a stored record
    localStorage.setItem(LOCK_STORAGE_KEY, await createLockRecord(p1));
    await saveRecoveryRecord(recoverPhrase.value, p1);
    setLocked(false);
  } catch (e) {
    recoverNewPassError.textContent = 'Error: ' + (e && e.message ? e.message : e);
    recoverNewPassError.style.display = 'block';
    recoverSetNewBtn.textContent = 'Set New Passcode & Enter';
    recoverSetNewBtn.disabled = false;
  }
});

recoverFullReset.addEventListener('click', () => {
  const ok = confirm("WARNING: A full reset wipes the local device lock, the recovery phrase, and any saved data for this domain. Continue?");
  if (ok) {
    localStorage.clear();
    initLock();
  }
});

recoverPhrase.addEventListener('keydown', (e) => { if (e.key === 'Enter') recoverBtn.click(); });
recoverNewPass.addEventListener('keydown', (e) => { if (e.key === 'Enter') recoverNewPassConfirm.focus(); });
recoverNewPassConfirm.addEventListener('keydown', (e) => { if (e.key === 'Enter') recoverSetNewBtn.click(); });

setupPassToggle('toggleRecoverNewPass', 'recoverNewPass');
setupPassToggle('toggleRecoverNewPassConfirm', 'recoverNewPassConfirm');

deviceResetBtn.addEventListener('click', () => {
  const confirmReset = confirm("Lock the application and reset passcode?");
  if (confirmReset) {
    localStorage.clear();
    initLock();
  }
});

UI.viewRecoveryBtn.addEventListener('click', async () => {
  const pw = prompt('Enter your device passcode to reveal the recovery phrase');
  if (pw === null) return;
  const record = localStorage.getItem(LOCK_STORAGE_KEY);
  if (!record || !(await verifyLockRecord(record, pw))) {
    logStatus('Incorrect device passcode.', true);
    return;
  }
  const phrase = await decryptRecoveryPhrase(pw);
  if (!phrase) {
    logStatus('No recovery phrase is stored on this device yet.', true);
    return;
  }
  logToConsole('Recovery phrase: ' + phrase, 'data');
  try {
    await navigator.clipboard.writeText(phrase);
    logStatus('Recovery phrase copied to clipboard — store it offline. It is the only way to recover a forgotten passcode.');
  } catch (e) {
    logStatus('Recovery phrase: ' + phrase, false);
  }
});

// Run lock initialization on load
window.addEventListener('load', () => {
  initLock();
  const probs = supportProblems();
  if (probs.length) {
    logToConsole('⚠️ ' + probs.join(' ') + ' Encryption and decryption will not work on this origin.', 'error');
  } else {
    logToConsole('Blackout v' + APP_VERSION + ' initialized — all required APIs available.');
  }
});

// ---------- Cloud Storage & Vault Event Handlers ----------

function openCloudModal() {
  if (!UI._currentArtifact) {
    logStatus('No generated artifact available to save. Execute a protocol first.', true);
    return;
  }
  UI.cloudModal.style.display = 'flex';
  UI.cloudModal.setAttribute('aria-hidden', 'false');
  UI.cloudModalStatus.style.display = 'none';
  UI.cloudContextNote.value = '';
}

function closeCloudModal() {
  UI.cloudModal.style.display = 'none';
  UI.cloudModal.setAttribute('aria-hidden', 'true');
}

if (UI.saveCloudBtn) UI.saveCloudBtn.addEventListener('click', openCloudModal);
if (UI.closeCloudModal) UI.closeCloudModal.addEventListener('click', closeCloudModal);
if (UI.cancelCloudModalBtn) UI.cancelCloudModalBtn.addEventListener('click', closeCloudModal);

// Radio provider toggle
document.querySelectorAll('input[name="cloudProvider"]').forEach(radio => {
  radio.addEventListener('change', (e) => {
    document.querySelectorAll('.provider-option').forEach(opt => opt.classList.remove('active'));
    const parentLabel = e.target.closest('.provider-option');
    if (parentLabel) parentLabel.classList.add('active');

    const provider = e.target.value;
    if (UI.gdriveAuthWrap) {
      UI.gdriveAuthWrap.style.display = (provider === 'gdrive') ? 'block' : 'none';
    }
  });
});

if (UI.confirmCloudSaveBtn) {
  UI.confirmCloudSaveBtn.addEventListener('click', async () => {
    if (!UI._currentArtifact) { closeCloudModal(); return; }

    const selectedProvider = document.querySelector('input[name="cloudProvider"]:checked')?.value || 'system';
    const note = UI.cloudContextNote ? UI.cloudContextNote.value : '';
    UI.cloudModalStatus.style.display = 'none';
    UI.confirmCloudSaveBtn.disabled = true;
    UI.confirmCloudSaveBtn.textContent = 'Saving…';

    try {
      if (selectedProvider === 'system') {
        const res = await window.BlackoutCloud.saveToSystemCloud(
          UI._currentArtifact.buffer,
          UI._currentArtifact.filename,
          UI._currentArtifact.mimeType,
          note
        );
        if (!res.canceled) {
          logStatus('Artifact saved to cloud storage folder: ' + (res.filename || UI._currentArtifact.filename));
          logToConsole('Saved ' + UI._currentArtifact.filename + ' to Cloud Vault with context note.', 'data');
          closeCloudModal();
        }
      } else if (selectedProvider === 'gdrive') {
        const token = window.BlackoutCloud.getCachedGoogleToken() || (UI.gdriveToken ? UI.gdriveToken.value.trim() : '');
        if (!token) {
          UI.cloudModalStatus.textContent = 'Please click "Sign In with Google" or enter an OAuth Token below.';
          UI.cloudModalStatus.style.display = 'block';
          return;
        }
        const res = await window.BlackoutCloud.uploadToGoogleDrive(
          token,
          UI._currentArtifact.buffer,
          UI._currentArtifact.filename,
          UI._currentArtifact.mimeType,
          note
        );
        logStatus('Uploaded ' + res.name + ' to Google Drive ("' + res.folder + '")');
        logToConsole('Uploaded to Google Drive Vault ID: ' + res.fileId, 'data');
        closeCloudModal();
      }
    } catch (e) {
      UI.cloudModalStatus.textContent = 'Cloud Save Error: ' + (e && e.message ? e.message : e);
      UI.cloudModalStatus.style.display = 'block';
      logToConsole('Cloud Save Error: ' + (e && e.message ? e.message : e), 'error');
    } finally {
      UI.confirmCloudSaveBtn.disabled = false;
      UI.confirmCloudSaveBtn.textContent = 'Save Artifact to Cloud';
    }
  });
}

// Import from Cloud Vault button
if (UI.importCloudBtn) {
  UI.importCloudBtn.addEventListener('click', async () => {
    try {
      const file = await window.BlackoutCloud.importFromSystemCloud();
      if (file) {
        const dt = new DataTransfer();
        dt.items.add(file);
        UI.fileIn.files = dt.files;
        UI.fileIn.dispatchEvent(new Event('change', { bubbles: true }));
        logStatus('Loaded cloud vault file: ' + file.name);
      }
    } catch (e) {
      if (e.name !== 'AbortError') {
        logStatus('Import Error: ' + (e && e.message ? e.message : e), true);
      }
    }
  });
}

// Google OAuth Sign-In Popup Button
if (UI.gdriveSignInBtn) {
  UI.gdriveSignInBtn.addEventListener('click', () => {
    const customId = UI.gdriveClientId ? UI.gdriveClientId.value : '';
    UI.gdriveSignInBtn.disabled = true;
    UI.gdriveSignInBtn.textContent = 'Opening Google Sign-In…';

    window.BlackoutCloud.requestGoogleOAuthToken(
      customId,
      (token) => {
        UI.gdriveSignInBtn.disabled = false;
        UI.gdriveSignInBtn.textContent = 'Connected to Google Drive ✓';
        UI.gdriveSignInBtn.style.background = 'rgba(0, 255, 136, 0.2)';
        if (UI.gdriveStatusText) {
          UI.gdriveStatusText.textContent = 'Authorized ✓ Ready to save file into your Google Drive Vault.';
          UI.gdriveStatusText.style.color = '#00ff88';
        }
        logToConsole('Google Drive OAuth authorized successfully.', 'data');
      },
      (err) => {
        UI.gdriveSignInBtn.disabled = false;
        UI.gdriveSignInBtn.textContent = 'Sign In with Google';
        if (UI.cloudModalStatus) {
          UI.cloudModalStatus.textContent = err;
          UI.cloudModalStatus.style.display = 'block';
        }
      }
    );
  });
}


