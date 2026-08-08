# Blackout

> Client-side steganography tool — compress, encrypt, and hide files inside PNG images.

Blackout lets you compress a file with **gzip**, encrypt it with **AES-256-GCM**
(PBKDF2-SHA-256 key derivation), and hide the encrypted payload inside a regular
PNG image ("camo PNG"). Everything runs **entirely in your browser** — nothing is
uploaded, no servers, no cloud. A local device-lock passcode gates the interface.

Live demo: <https://hanserq.github.io/Blackout/>

## Features

- **Encrypt, Compress & Hide → PNG** — default workflow: compress + encrypt a file and embed it in a PNG cover.
- **Custom output names** — name the artifact on encrypt *or* decrypt; encrypt modes auto-append the right extension and decrypt restores the original name when left empty.
- **Raw `.blackout` containers** — same compression + encryption without the PNG wrapper.
- **Decrypt & Decompress** — restores the original file (and its filename) from a `.blackout` or camo PNG.
- **Camo / Decamo** — embed an existing container into a PNG, or extract it back out.
- **Nested Re-encrypt** — wrap any file in a new encrypted container (opaque wrapping).
- **Diagnostics** — inspect PNG chunk structure and verify embedded metadata.
- **Device lock** — PBKDF2-SHA-256 (150k iterations, salted) passcode stored in `localStorage`, with automatic migration from the legacy SHA-256 format.
- **Offline recovery phrase** — an 8-word phrase shown at setup unlocks a forgotten passcode and lets you set a new one; the phrase is stored only as a PBKDF2 hash plus an AES-GCM copy encrypted under the passcode, and can be re-shown from the app.
- No dependencies, no build step — pure HTML/CSS/JS.

## Modes

| Mode | Input → Output | Notes |
|---|---|---|
| `encrypt` (default) | file + password + optional cover → `.png` | Auto-forges a 1024×1024 black PNG if no cover is chosen; custom output name supported |
| `encrypt-raw` | file + password → `.blackout` | Advanced; no PNG wrapper; custom output name supported |
| `decrypt` | `.blackout` **or** camo PNG + password → original file | Restores original filename unless overridden (custom name supported) |
| `camo` | existing `.blackout` + cover → `.camo.png` | Validates the `BLKOUT01` magic prefix first; no password needed |
| `decamo` | camo PNG → extracted `.blackout` | No password needed — extraction only; security lives in the decrypt step |

### Diagnostics buttons

- **Nested Re-encrypt** — wraps the selected file opaquely (`file.reencrypted.blackout`).
  To unwrap, decrypt once to get the inner `.blackout`, then decrypt again with the *original* password.
- **Inspect PNG Payload** — lists all PNG chunks (length/type) in the selected image.
- **Verify Metadata** — decrypts and prints the embedded `{name, type, size, createdAt, ...}` metadata (requires password).

## File formats (compatibility contract)

> ⚠️ These layouts are stable. Changing any byte layout, the magic string, the
> PBKDF2 iteration count, or the salt/IV sizes breaks decryption of existing files.
> If the format ever needs to evolve, introduce a new magic version (e.g.
> `BLKOUT02`) with a backward-compatible decrypt path.

### 1. Encrypted container (`.blackout` / camo payload)

```
"BLKOUT01" (8-byte ASCII magic) | salt (16 bytes) | IV (12 bytes) | AES-256-GCM ciphertext
```

- Key derivation: **PBKDF2-SHA-256, 150,000 iterations** → AES-256-GCM key.
- Fresh random salt + IV on every encryption, so ciphertexts are unique.

### 2. Plaintext with metadata (what gets encrypted)

```
metaLen (4 bytes big-endian) | metadata JSON | gzip(file bytes)
```

- Metadata JSON: `{"name","type","size","compressed":true,"compression":"gzip","createdAt"}`.
- `parsePlainWithMetadata` falls back to `{name:'output'}` if the JSON is unparseable.

### 3. Camo PNG

- The encrypted container is inserted as a PNG chunk typed **`bLoK`** immediately
  before `IEND`: `len(4B) | "bLoK" | payload | CRC32(IEEE over type+data)`.
- Extraction walks chunks and returns the first `bLoK`. Decrypt auto-detects PNG
  input and extracts before decrypting.
- ⚠️ Image optimizers / re-compressors may strip unknown chunks. Keep backups of
  camo PNGs.

## Device lock & recovery

- On first launch you set a device passcode and are shown an **8-word offline recovery phrase** (from a ~1,100-word pool, ≈ 80 bits). You must acknowledge saving it before setup completes.
- The phrase is stored under `localStorage["blackout_recovery"]` in two forms:
  1. a **PBKDF2-SHA-256 hash** (random salt, 150k iterations) used to verify it offline — you can recover on a machine with no network access;
  2. the phrase **AES-256-GCM encrypted under the device passcode**, so **Show Recovery Phrase** in the app can re-display it after you enter the passcode.
- **Forgot?** on the lock screen verifies your phrase and lets you set a *new* passcode (the phrase itself is kept and re-encrypted under the new passcode). If no recovery phrase exists on the device, *Forgot?* falls back to a full local reset.
- **Full device reset** (from the recovery view, *Forgot?*, or *Reset Device Lock* in the footer) wipes the lock, the recovery phrase, and all `localStorage` data for the domain.

## Security notes

- Encryption keys are derived per-file and **never persisted**; the password lives
  only in memory for the session.
- The device-lock passcode is stored as a **PBKDF2-SHA-256 v2 record** (random
  16-byte salt, 150k iterations) under `localStorage["blackout_app_lock"]`;
  legacy SHA-256 digests are migrated on next successful unlock. It gates the
  UI, not the cryptography — anyone with devtools access can bypass it (the
  recovery phrase protects against *forgetting* the passcode, not against a
  determined attacker on the same device).
- `localStorage.clear()` (Forgot / Reset Device Lock) wipes **all** data for the
  domain.
- The tool is a convenience layer over Web Crypto; it does not replace a reviewed
  end-to-end encryption product for high-assurance use.

## Browser support

- Requires a **secure context** (HTTPS or `localhost`) for `crypto.subtle`.
- Requires `CompressionStream` / `DecompressionStream` — Chrome, Edge, Firefox,
  Safari **16.4+**.
- The app checks for these APIs on load and reports missing ones.

## Local usage

No build step. Open `index.html` directly or serve the folder:

```bash
python3 -m http.server 8000
# → http://localhost:8000/
```

## Deployment

GitHub Pages is deployed automatically by `.github/workflows/static.yml` on every
push to `main` — the whole repo is uploaded as static content.

## Development

- `index.html` — all UI markup and element IDs.
- `app.js` — UI wiring, crypto, compression, PNG chunk handling, lock screen.
- `style.css` — dark glassmorphism theme, responsive, reduced-motion aware.

Keep the formats in the [File formats](#file-formats-compatibility-contract)
section unchanged when adding features.

## License

MIT © 2025 Rakhib. See [LICENSE](LICENSE).
