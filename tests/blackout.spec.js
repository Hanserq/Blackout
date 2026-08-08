// Blackout end-to-end tests: device lock, encrypt/decrypt round-trip, camo, text mode.
const { test, expect } = require('playwright/test');
const fs = require('fs');

const PASSWORD = 'CorrectHorseBatteryStaple!2026';
const SECRET_TEXT = 'Top secret: the cake is a lie. 你好, мир! 🎉 1234567890';

// Minimal valid 1x1 transparent PNG.
const TINY_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64'
);

async function unlockApp(page) {
  const setup = page.locator('#setupMode');
  const didSetup = await setup.isVisible();
  if (didSetup) {
    await page.fill('#setupPass', PASSWORD);
    await page.fill('#setupPassConfirm', PASSWORD);
    await page.check('#recoverAck');
    await page.click('#setPassBtn');
  } else {
    await page.fill('#unlockPass', PASSWORD);
    await page.click('#unlockBtn');
  }
  // Unlocking is async (PBKDF2 derivation). Wait for the real unlock state —
  // `#goBtn` is "visible" even behind the overlay, which hid a race where the
  // password fill ran while the app was still locked/inert and got swallowed.
  await expect(page.locator('#lock')).toHaveAttribute('aria-hidden', 'true');
  await expect(page.locator('#app')).not.toHaveAttribute('inert', '');
  if (didSetup) {
    // the recovery record is persisted in the background — wait for it so a
    // later reload can never race the write
    await expect.poll(() => page.evaluate(() => !!localStorage.getItem('blackout_recovery'))).toBe(true);
  }
  await expect(page.locator('#goBtn')).toBeVisible();
}

async function runEncryptRaw(page, payload, name) {
  await page.selectOption('#mode', 'encrypt-raw');
  await page.fill('#password', PASSWORD);
  await page.setInputFiles('#fileIn', { name, mimeType: 'application/octet-stream', buffer: payload });
  await page.click('#goBtn');
  const dl = page.waitForEvent('download');
  await page.click('#downloadBtn');
  const download = await dl;
  expect(download.suggestedFilename()).toMatch(/\.blackout$/);
  const p = await download.path();
  return fs.readFileSync(p);
}

async function runDecrypt(page, container, name) {
  await page.selectOption('#mode', 'decrypt');
  await page.fill('#password', PASSWORD);
  await page.setInputFiles('#fileIn', { name, mimeType: 'application/octet-stream', buffer: container });
  await page.click('#goBtn');
  const dl = page.waitForEvent('download');
  await page.click('#downloadBtn');
  const download = await dl;
  const p = await download.path();
  return fs.readFileSync(p);
}

test.describe('Blackout', () => {

  test('device lock: setup, persist across reload, reject wrong passcode', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('#setupMode')).toBeVisible();

    // recovery phrase is shown and setup is gated on acknowledging it
    const phrase = (await page.locator('#recoverPhraseOut').textContent()).trim();
    expect(phrase.split(/\s+/).length).toBe(8);

    // set button is disabled until the recovery phrase is acknowledged
    await page.fill('#setupPass', PASSWORD);
    await page.fill('#setupPassConfirm', PASSWORD);
    await expect(page.locator('#setPassBtn')).toBeDisabled();
    await page.check('#recoverAck');
    await expect(page.locator('#setPassBtn')).toBeEnabled();

    // mismatched passcodes are rejected
    await page.fill('#setupPassConfirm', 'different-pass');
    await page.click('#setPassBtn');
    await expect(page.locator('#setupError')).toContainText('do not match');
    await expect(page.locator('#setupMode')).toBeVisible();

    // correct setup unlocks (async PBKDF2 — wait for the real unlock state)
    await page.fill('#setupPassConfirm', PASSWORD);
    await page.click('#setPassBtn');
    await expect(page.locator('#lock')).toHaveAttribute('aria-hidden', 'true');
    await expect.poll(() => page.evaluate(() => !!localStorage.getItem('blackout_recovery'))).toBe(true);
    await expect(page.locator('#goBtn')).toBeVisible();

    // persists across reload → unlock mode
    await page.reload();
    await expect(page.locator('#unlockMode')).toBeVisible();
    await page.fill('#unlockPass', 'wrong-passcode');
    await page.click('#unlockBtn');
    await expect(page.locator('#unlockError')).toContainText('Invalid device passcode');
    // the app stays locked: overlay is shown (aria-hidden="false") and the app is inert
    await expect(page.locator('#lock')).toHaveAttribute('aria-hidden', 'false');
    await expect(page.locator('#app')).toHaveAttribute('inert', '');

    // correct passcode unlocks
    await page.fill('#unlockPass', PASSWORD);
    await page.click('#unlockBtn');
    await expect(page.locator('#goBtn')).toBeVisible();
  });

  test('encrypt-raw → decrypt round-trips arbitrary binary data', async ({ page }) => {
    await page.goto('/');
    await unlockApp(page);

    const payload = Buffer.from(Array.from({ length: 8192 }, (_, i) => (i * 7 + 13) % 256));
    const container = await runEncryptRaw(page, payload, 'payload.bin');
    expect(container.length).toBeGreaterThan(0);

    // wrong password → friendly error, no artifact
    await page.selectOption('#mode', 'decrypt');
    await page.fill('#password', 'definitely-wrong');
    await page.setInputFiles('#fileIn', { name: 'bad.blackout', mimeType: 'application/octet-stream', buffer: container });
    await page.click('#goBtn');
    await expect(page.locator('#status')).toContainText('Wrong password');

    const restored = await runDecrypt(page, container, 'payload.bin.blackout');
    expect(restored.equals(payload)).toBe(true);
  });

  test('camo: embed into PNG cover, decamo, decrypt', async ({ page }) => {
    await page.goto('/');
    await unlockApp(page);

    const payload = Buffer.from('secret file contents — camo round trip');
    const container = await runEncryptRaw(page, payload, 'notes.txt');

    // camo: embed container into a PNG cover
    await page.selectOption('#mode', 'camo');
    await page.setInputFiles('#fileIn', { name: 'container.blackout', mimeType: 'application/octet-stream', buffer: container });
    await page.setInputFiles('#coverIn', { name: 'cover.png', mimeType: 'image/png', buffer: TINY_PNG });
    await page.click('#goBtn');
    let dl = page.waitForEvent('download');
    await page.click('#downloadBtn');
    const camoPng = fs.readFileSync(await (await dl).path());

    // the camo PNG must still be a valid PNG (signature intact)
    expect(camoPng.subarray(0, 8)).toEqual(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));

    // decamo: pull the .blackout back out
    await page.selectOption('#mode', 'decamo');
    await page.setInputFiles('#fileIn', { name: 'cover.camo.png', mimeType: 'image/png', buffer: camoPng });
    await page.click('#goBtn');
    dl = page.waitForEvent('download');
    await page.click('#downloadBtn');
    const extracted = fs.readFileSync(await (await dl).path());
    expect(extracted.equals(container)).toBe(true);

    const restored = await runDecrypt(page, extracted, 'notes.txt.blackout');
    expect(restored.toString()).toBe(payload.toString());
  });

  test('text mode: encrypt message → decrypt shows exact message', async ({ page }) => {
    await page.goto('/');
    await unlockApp(page);

    // encrypt text (no cover → raw .blackout)
    await page.selectOption('#mode', 'text-encrypt');
    await expect(page.locator('#textWrap')).toBeVisible();
    await page.fill('#textInput', SECRET_TEXT);
    await page.fill('#password', PASSWORD);
    await page.click('#goBtn');
    let dl = page.waitForEvent('download');
    await page.click('#downloadBtn');
    const container = fs.readFileSync(await (await dl).path());

    // decrypt text back
    await page.selectOption('#mode', 'text-decrypt');
    await expect(page.locator('#textWrap')).toBeVisible();
    await page.setInputFiles('#fileIn', { name: 'message.txt.blackout', mimeType: 'application/octet-stream', buffer: container });
    await page.click('#goBtn');
    await expect(page.locator('#status')).toContainText('Message decrypted');
    await expect(page.locator('#textInput')).toHaveValue(SECRET_TEXT);
  });

  test('text mode: encrypt message into camo PNG, decrypt from PNG', async ({ page }) => {
    await page.goto('/');
    await unlockApp(page);

    await page.selectOption('#mode', 'text-encrypt');
    await page.fill('#textInput', 'hidden inside a picture');
    await page.fill('#password', PASSWORD);
    await page.setInputFiles('#coverIn', { name: 'cover.png', mimeType: 'image/png', buffer: TINY_PNG });
    await page.click('#goBtn');
    let dl = page.waitForEvent('download');
    await page.click('#downloadBtn');
    const camoPng = fs.readFileSync(await (await dl).path());

    await page.selectOption('#mode', 'text-decrypt');
    await page.setInputFiles('#fileIn', { name: 'cover.png', mimeType: 'image/png', buffer: camoPng });
    await page.click('#goBtn');
    await expect(page.locator('#textInput')).toHaveValue('hidden inside a picture');
  });

  test('password generator produces a strong password', async ({ page }) => {
    await page.goto('/');
    await unlockApp(page);

    await page.click('#genPassBtn');
    const pw = await page.inputValue('#password');
    expect(pw.length).toBeGreaterThanOrEqual(20);
    expect(pw).toMatch(/[a-z]/);
    expect(pw).toMatch(/[A-Z]/);
    expect(pw).toMatch(/[0-9]/);
    expect(pw).toMatch(/[^A-Za-z0-9]/);
    await expect(page.locator('#strengthLabel')).toHaveText('Strong');
  });

  test('recovery phrase: forgot passcode → recover → set new passcode', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('#setupMode')).toBeVisible();

    // capture the displayed phrase and complete setup
    const phrase = (await page.locator('#recoverPhraseOut').textContent()).trim();
    expect(phrase.split(/\s+/).length).toBe(8);
    await page.fill('#setupPass', PASSWORD);
    await page.fill('#setupPassConfirm', PASSWORD);
    await page.check('#recoverAck');
    await page.click('#setPassBtn');
    await expect(page.locator('#lock')).toHaveAttribute('aria-hidden', 'true');
    await expect.poll(() => page.evaluate(() => !!localStorage.getItem('blackout_recovery'))).toBe(true);
    await expect(page.locator('#goBtn')).toBeVisible();

    // lock again and open the recovery flow
    await page.reload();
    await expect(page.locator('#unlockMode')).toBeVisible();
    await page.click('#forgotBtn');
    await expect(page.locator('#recoverMode')).toBeVisible();

    // a wrong phrase is rejected
    await page.fill('#recoverPhrase', 'wrong wrong wrong wrong wrong wrong wrong wrong');
    await page.click('#recoverBtn');
    await expect(page.locator('#recoverError')).toContainText('not valid');

    // the correct phrase unlocks the new-passcode step
    await page.fill('#recoverPhrase', phrase);
    await page.click('#recoverBtn');
    await expect(page.locator('#recoverSetNew')).toBeVisible();

    const NEW_PASS = 'BrandNewPasscode!77';
    await page.fill('#recoverNewPass', NEW_PASS);
    await page.fill('#recoverNewPassConfirm', NEW_PASS);
    await page.click('#recoverSetNewBtn');
    await expect(page.locator('#lock')).toHaveAttribute('aria-hidden', 'true');
    await expect.poll(() => page.evaluate(() => !!localStorage.getItem('blackout_recovery'))).toBe(true);
    await expect(page.locator('#goBtn')).toBeVisible();

    // old passcode no longer works; the new one does
    await page.reload();
    await expect(page.locator('#unlockMode')).toBeVisible();
    await page.fill('#unlockPass', PASSWORD);
    await page.click('#unlockBtn');
    await expect(page.locator('#unlockError')).toContainText('Invalid device passcode');
    await page.fill('#unlockPass', NEW_PASS);
    await page.click('#unlockBtn');
    await expect(page.locator('#goBtn')).toBeVisible();
  });

  test('auto-mode suggests decrypt when a .blackout file is selected', async ({ page }) => {
    await page.goto('/');
    await unlockApp(page);

    await page.selectOption('#mode', 'encrypt');
    await page.setInputFiles('#fileIn', { name: 'secret.blackout', mimeType: 'application/octet-stream', buffer: Buffer.from('BLKOUT01') });
    await expect(page.locator('#mode')).toHaveValue('decrypt');
  });

  test('custom output name works for both encrypt and decrypt', async ({ page }) => {
    await page.goto('/');
    await unlockApp(page);
    const payload = Buffer.from('named round trip');

    // encrypt-raw with a custom output name (auto-appends .blackout)
    await page.selectOption('#mode', 'encrypt-raw');
    await page.fill('#password', PASSWORD);
    await page.fill('#outputName', 'my-custom');
    await page.setInputFiles('#fileIn', { name: 'notes.txt', mimeType: 'text/plain', buffer: payload });
    await page.click('#goBtn');
    let dl = page.waitForEvent('download');
    await page.click('#downloadBtn');
    let download = await dl;
    expect(download.suggestedFilename()).toBe('my-custom.blackout');
    const container = fs.readFileSync(await download.path());

    // decrypt with a custom output name (used as-is)
    await page.selectOption('#mode', 'decrypt');
    await page.fill('#password', PASSWORD);
    await page.fill('#outputName', 'restored.txt');
    await page.setInputFiles('#fileIn', { name: 'my-custom.blackout', mimeType: 'application/octet-stream', buffer: container });
    await page.click('#goBtn');
    dl = page.waitForEvent('download');
    await page.click('#downloadBtn');
    download = await dl;
    expect(download.suggestedFilename()).toBe('restored.txt');
    expect(fs.readFileSync(await download.path()).equals(payload)).toBe(true);
  });

  test('camo mode works without a password', async ({ page }) => {
    await page.goto('/');
    await unlockApp(page);

    await page.selectOption('#mode', 'camo');
    await page.setInputFiles('#fileIn', { name: 'container.blackout', mimeType: 'application/octet-stream', buffer: Buffer.from('BLKOUT01' + 'x'.repeat(64)) });
    await page.setInputFiles('#coverIn', { name: 'cover.png', mimeType: 'image/png', buffer: TINY_PNG });
    await page.click('#goBtn');
    const dl = page.waitForEvent('download');
    await page.click('#downloadBtn');
    const download = await dl;
    expect(download.suggestedFilename()).toMatch(/\.camo\.png$/);
    const out = fs.readFileSync(await download.path());
    expect(out.subarray(0, 8)).toEqual(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  });
});
