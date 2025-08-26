/* Lock logic (redirect mode) */
const MODE = 'redirect';            // 'redirect' -> go to MAIN_URL after unlock
const MAIN_URL = 'blackoutv1.9.2.html'; // your main app file (same folder)
const LS_KEY = 'blackout.lock.hash';
const SALT   = 'blackout-lock-v1';

(async () => {
  const overlay   = document.getElementById('lockOverlay');
  const lockSub   = document.getElementById('lockSub');
  const pins      = Array.from(document.querySelectorAll('#unlockForm .pin'));
  const unlockForm= document.getElementById('unlockForm');
  const firstTime = document.getElementById('firstTime');
  const setupForm = document.getElementById('setupForm');
  const newPin    = document.getElementById('newPin');
  const newPin2   = document.getElementById('newPin2');
  const resetLock = document.getElementById('resetLock');
  const btnLock   = document.getElementById('btnLock');

  const getHash = () => localStorage.getItem(LS_KEY);
  const setHash = (h) => localStorage.setItem(LS_KEY, h);
  const sha256 = async (s) => {
    const dig = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(SALT + s));
    return [...new Uint8Array(dig)].map(b=>b.toString(16).padStart(2,'0')).join('');
  };
  const show = (el)=>el.classList.remove('hidden');
  const hide = (el)=>el.classList.add('hidden');

  function showOverlay(first=false){
    overlay.hidden = false; overlay.setAttribute('aria-hidden','false');
    if (first) { lockSub.textContent = 'Create a new passcode to continue'; show(firstTime); newPin.focus(); }
    else       { lockSub.textContent = 'Enter your 4-digit passcode';        hide(firstTime); pins[0].focus(); }
  }
  function unlockUI(){
    if (MODE === 'redirect') { window.location.replace(MAIN_URL); return; }
  }

  pins.forEach((el,i)=>{
    el.addEventListener('input', ()=>{
      el.value = el.value.replace(/\D/g,'').slice(0,1);
      if (el.value && i < pins.length-1) pins[i+1].focus();
      if (pins.every(p=>p.value)) unlockForm.requestSubmit();
    });
    el.addEventListener('keydown', e=>{ if (e.key==='Backspace' && !el.value && i>0) pins[i-1].focus(); });
  });

  unlockForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const stored = getHash();
    if (!stored) { showOverlay(true); return; }
    const pin = pins.map(p=>p.value).join('');
    if (pin.length !== 4) return;
    const ok = await sha256(pin) === stored;
    if (ok) unlockUI(); else { lockSub.textContent = 'Wrong passcode. Try again.'; pins.forEach(p=>p.value=''); pins[0].focus(); }
  });

  setupForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const p1 = (newPin.value||'').replace(/\D/g,'');
    const p2 = (newPin2.value||'').replace(/\D/g,'');
    if (p1.length!==4 || p2.length!==4) return alert('Enter 4 digits in both fields');
    if (p1!==p2) return alert('PINs do not match');
    setHash(await sha256(p1)); pins.forEach(p=>p.value=''); newPin.value=newPin2.value=''; unlockUI();
  });

  resetLock.addEventListener('click', ()=>{
    if (confirm('Clear saved lock?')) { localStorage.removeItem(LS_KEY); showOverlay(true); }
  });

  btnLock?.addEventListener('click', ()=> showOverlay(!!getHash()===false));

  // On load
  if (getHash()) showOverlay(false); else showOverlay(true);
})();