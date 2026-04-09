/* Blackout Logic: UI Events, Crypto, Compression and PNG Steganography */

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
  coverIn: document.getElementById('coverIn'),
  coverLabel: document.getElementById('coverLabel'),
  makeBlackCover: document.getElementById('makeBlackCover'),
  useDemoCover: document.getElementById('useDemoCover'),
  decryptName: document.getElementById('decryptName'),
};

function logStatus(txt, isError=false) {
  UI.status.style.display='block';
  UI.status.textContent = txt;
  UI.status.style.color = isError ? '#ffb3b3' : '';
}

function hideStatus(){ UI.status.style.display='none' }

function readU32(bytes, off) { return (bytes[off]<<24) | (bytes[off+1]<<16) | (bytes[off+2]<<8) | (bytes[off+3]); }
function writeU32(v) { return new Uint8Array([(v>>>24)&255,(v>>>16)&255,(v>>>8)&255,v&255]); }

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
async function buildPlainWithMetadata(file) {
  const ab = await fileToArrayBuffer(file);
  const compressedAb = await compressBytes(new Uint8Array(ab));
  
  const meta = { 
    name: file.name, 
    type: file.type || 'application/octet-stream', 
    size: file.size, 
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
  return new Promise((res, rej)=>{
    const r = new FileReader();
    r.onload = ()=> res(r.result);
    r.onerror = ()=> rej(r.error);
    r.readAsArrayBuffer(file);
  });
}

function saveAsFile(buf, filename, mimeType) {
  const blob = new Blob([buf], {type: mimeType || 'application/octet-stream'});
  const url = URL.createObjectURL(blob);
  UI.downloadBtn.style.display='inline-block';
  UI.downloadBtn.onclick = ()=> {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
  };
  UI.lastOut.textContent = filename + ' (ready to download)';
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

function toggleCoverUI() {
  const mode = UI.mode.value;
  if (mode === 'encrypt' || mode === 'camo') {
    UI.coverIn.style.display='block';
    UI.coverLabel.style.display='block';
    UI.makeBlackCover.style.display='inline-block';
    UI.useDemoCover.style.display='inline-block';
  } else {
    UI.coverIn.style.display='none';
    UI.coverLabel.style.display='none';
    UI.makeBlackCover.style.display='none';
    UI.useDemoCover.style.display='none';
  }
}
UI.mode.addEventListener('change', toggleCoverUI);
toggleCoverUI();

UI.makeBlackCover.addEventListener('click', async ()=> {
  try {
    const blob = await makeBlackPngBlob(1024,1024);
    setFileInputFromBlob(UI.coverIn, blob, 'black_cover.png');
    logStatus('Black cover generated and selected.');
  } catch (e) { logStatus('Error generating black PNG: '+e.message, true); }
});

UI.useDemoCover.addEventListener('click', async ()=> {
  const c = document.createElement('canvas'); c.width=512; c.height=512;
  const ctx = c.getContext('2d');
  ctx.fillStyle='#071019'; ctx.fillRect(0,0,512,512);
  ctx.fillStyle='#00ff88'; ctx.fillRect(40,40,432,432);
  c.toBlob(b=> { setFileInputFromBlob(UI.coverIn, b, 'demo_cover.png'); logStatus('Demo cover selected.'); }, 'image/png');
});

// Main actions
UI.goBtn.addEventListener('click', async ()=> {
  hideStatus();
  const file = UI.fileIn.files[0];
  const pass = UI.password.value;
  const mode = UI.mode.value;
  try {
    if ((mode === 'encrypt' || mode === 'encrypt-raw' || mode === 'camo') && !file) { logStatus('Select an input file first', true); return; }
    if ((mode==='encrypt' || mode==='encrypt-raw' || mode==='camo' || mode==='decrypt') && (!pass)) { logStatus('Provide a password', true); return; }

    UI.goBtn.textContent = 'Processing...';
    UI.goBtn.disabled = true;

    if (mode === 'encrypt-raw') {
      const plain = await buildPlainWithMetadata(file);
      const container = await encryptBytes(plain, pass);
      saveAsFile(container, file.name + '.blackout', 'application/octet-stream');
      logStatus('Encrypted raw container ready (.blackout) (Compressed)');
    }

    else if (mode === 'encrypt') {
      const plain = await buildPlainWithMetadata(file);
      const container = await encryptBytes(plain, pass);
      let coverFile = UI.coverIn.files[0];
      if (!coverFile) {
        const blob = await makeBlackPngBlob(1024,1024);
        coverFile = new File([blob], (file.name || 'cover') + '.png', {type:'image/png'});
      }
      const pngAb = await fileToArrayBuffer(coverFile);
      const out = insertPngCamo(new Uint8Array(pngAb), new Uint8Array(container));
      const outName = coverFile.name.replace(/\.png$/i, '') + '.png';
      saveAsFile(out.buffer, outName, 'image/png');
      logStatus('Compressed, encrypted, and embedded into PNG. Saved as ' + outName);
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
      const pngAb = await fileToArrayBuffer(coverFile);
      const out = insertPngCamo(new Uint8Array(pngAb), new Uint8Array(inputAb));
      const outName = coverFile.name.replace(/\.png$/i, '') + '.camo.png';
      saveAsFile(out.buffer, outName, 'image/png');
      logStatus('Embedded existing container into PNG. Saved as ' + outName);
    }

    else if (mode === 'decrypt') {
      const ab = await fileToArrayBuffer(file);
      let containerBuf = ab;
      if (isPng(new Uint8Array(ab))) {
        try {
          const payload = extractPngCamo(new Uint8Array(ab));
          containerBuf = payload.buffer;
        } catch (e) { }
      }
      const pt = await decryptBytes(containerBuf, pass);
      const parsed = await parsePlainWithMetadata(pt);
      const suggested = UI.decryptName.value.trim() || (parsed.meta && parsed.meta.name) || ('decrypted.bin');
      saveAsFile(parsed.fileBytes.buffer, suggested, parsed.meta.type || 'application/octet-stream');
      logStatus('Decrypted and decompressed — ready to download as ' + suggested);
    }

    else if (mode === 'decamo') {
      const file2 = UI.fileIn.files[0];
      if (!file2) { logStatus('Select PNG input', true); return; }
      const pngAb = await fileToArrayBuffer(file2);
      const payload = extractPngCamo(new Uint8Array(pngAb));
      saveAsFile(payload.buffer, 'extracted-' + file2.name + '.blackout', 'application/octet-stream');
      logStatus('Extracted payload saved as raw .blackout. Use Decrypt mode to restore file.');
    }

  } catch (e) {
    logStatus('Error: ' + (e && e.message ? e.message : String(e)), true);
    console.error(e);
  } finally {
    UI.goBtn.textContent = 'Go';
    UI.goBtn.disabled = false;
  }
});

// nested re-encrypt
UI.reencryptBtn.addEventListener('click', async ()=> {
  const file = UI.fileIn.files[0];
  const pass = UI.password.value;
  if (!file || !pass) { logStatus('Provide .blackout file and new password', true); return; }
  try {
    const ab = await fileToArrayBuffer(file);
    const wrapped = await encryptBytes(ab, pass);
    saveAsFile(wrapped, file.name + '.reencrypted.blackout', 'application/octet-stream');
    logStatus('Re-encrypted nested container ready');
  } catch (e) {
    logStatus('Error: '+e.message, true);
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
    UI.lastOut.textContent = JSON.stringify(chunks, null, 2);
    UI.downloadBtn.style.display='none';
    hideStatus();
  } catch (e) {
    logStatus('Error: '+e.message, true);
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
    UI.lastOut.textContent = 'metadata: ' + JSON.stringify(parsed.meta, null, 2);
    UI.downloadBtn.style.display='none';
    hideStatus();
  } catch (e) {
    logStatus('Error reading metadata: '+e.message, true);
  }
});

UI.clearBtn.addEventListener('click', ()=> {
  UI.fileIn.value=''; UI.coverIn.value=''; UI.password.value=''; UI.decryptName.value=''; UI.lastOut.textContent='No output yet.'; UI.downloadBtn.style.display='none'; hideStatus();
});

/* Lock overlay Logic With Persistent Hashing */
const lockEl = document.getElementById('lock');
const setupMode = document.getElementById('setupMode');
const unlockMode = document.getElementById('unlockMode');

const setupPass = document.getElementById('setupPass');
const setupPassConfirm = document.getElementById('setupPassConfirm');
const setPassBtn = document.getElementById('setPassBtn');
const setupError = document.getElementById('setupError');

const unlockPass = document.getElementById('unlockPass');
const unlockBtn = document.getElementById('unlockBtn');
const forgotBtn = document.getElementById('forgotBtn');
const unlockError = document.getElementById('unlockError');

const deviceResetBtn = document.getElementById('deviceResetBtn');

// Helper to hash passcode for local storage
async function hashPasscode(pass) {
  const msgBuffer = new TextEncoder().encode(pass);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function initLock() {
  const savedHash = localStorage.getItem('blackout_app_lock');
  if (savedHash) {
    unlockMode.style.display = 'block';
    setupMode.style.display = 'none';
    unlockPass.value = '';
    unlockPass.focus();
  } else {
    setupMode.style.display = 'block';
    unlockMode.style.display = 'none';
    setupPass.value = '';
    setupPassConfirm.value = '';
    setupPass.focus();
  }
  lockEl.setAttribute('aria-hidden', 'false');
}

setPassBtn.addEventListener('click', async () => {
  setupError.style.display = 'none';
  const p1 = setupPass.value;
  const p2 = setupPassConfirm.value;
  
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
  
  const hash = await hashPasscode(p1);
  localStorage.setItem('blackout_app_lock', hash);
  lockEl.setAttribute('aria-hidden', 'true');
});

unlockBtn.addEventListener('click', async () => {
  unlockError.style.display = 'none';
  const p = unlockPass.value;
  if (!p) return;
  
  const hash = await hashPasscode(p);
  const savedHash = localStorage.getItem('blackout_app_lock');
  
  if (hash === savedHash) {
    lockEl.setAttribute('aria-hidden', 'true');
  } else {
    unlockError.textContent = 'Invalid device passcode.';
    unlockError.style.display = 'block';
  }
});

unlockPass.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') unlockBtn.click();
});

forgotBtn.addEventListener('click', () => {
  const confirmReset = confirm("WARNING: Resetting will wipe the current local device lock and any saved data associated with this browser. Continue?");
  if (confirmReset) {
    localStorage.clear();
    initLock();
  }
});

deviceResetBtn.addEventListener('click', () => {
  const confirmReset = confirm("Lock the application and reset passcode?");
  if (confirmReset) {
    localStorage.clear();
    initLock();
  }
});

// Run lock initialization on load
window.addEventListener('load', initLock);
