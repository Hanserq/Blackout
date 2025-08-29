# Blackout v2

Blackout is a fully offline, client-side encryption tool that hides any file inside a PNG image (or an optional raw container).  
The app runs entirely in the browser using the Web Crypto API, so no data ever leaves your device.

## Features

- **Encrypt any file** into a PNG that looks like a normal image  
- **Decrypt** the PNG back to the exact original file  
- **Optional cover image**: use an existing image as the carrier so the output looks natural  
- **Stored filename**: embed the original filename for restoration on decrypt  
- **Multiple vaults**: keep encrypted logs of all your encrypted files, unlocked only with the App Lock passcode  
- **Strong cryptography**: AES-256-GCM with PBKDF2-SHA256 (configurable iterations)  
- **Offline by design**: runs locally in the browser with no network required  
- **Responsive UI**: mobile and desktop friendly layout  
- **Help tutorial**: built-in walkthrough for new users  

## Getting Started

### Run Locally
1. Clone this repository or download the source.
2. Open `index.html` in a modern browser (Chrome, Firefox, Safari, Edge).
3. Set up an App Lock passcode on first launch.
4. Use the **Encrypt** and **Decrypt** panels to protect your files.

### No Build Step
Blackout is a pure HTML, CSS, and JavaScript app. No server, no backend, no dependencies.

## Usage

### Encrypt
1. Drop a file or choose one.
2. Enter a passphrase and select KDF strength.
3. Optionally provide:
   - A stored filename (restored on decrypt)
   - A cover image (used as camouflage)
4. Leave the output filename blank to auto-generate a safe random name.
5. Click **Encrypt** to download your PNG.

### Decrypt
1. Drop the PNG into the Decrypt panel.
2. Enter the correct passphrase.
3. Click **Decrypt** to restore the original file with its name and type.

### Vaults
- Create one or more vaults to keep a log of encrypted files.  
- Vaults are encrypted at rest and require the App Lock passcode to unlock.  
- You can rename, export, clear, or delete vaults at any time.  
- Set one vault as **Active** to automatically log future encryptions.

## Project Structure
```project-root/
├── index.html
│ └─ Landing page with App Lock. Users must unlock with a passcode
│ before accessing the main app.
│
├── blackoutv1.9.2.html
│ └─ Main application interface:
│ - Encrypt panel (file → PNG or container)
│ - Decrypt panel (PNG/container → file)
│ - Vaults card (multi-vault encrypted logs)
│ - Help/Tutorial modal
│
├── service-worker.js
│ └─ Handles offline caching and PWA functionality.
│ Ensures the app can run without internet once installed.
│
├── manifest.webmanifest
│ └─ PWA manifest: app name, icons, theme color, and install settings.
│
├── README.md
│ └─ Documentation (this file).
```

## How It Works (Technical Overview)

Blackout uses a **PNG container format** with a hidden encrypted payload.

1. **File preparation**
   - Original file is read as raw bytes.
   - Metadata (filename, extension, MIME type, size) is embedded alongside the file bytes.
   - Padding is added to align data to fixed-size blocks.

2. **Encryption**
   - A random salt and nonce are generated.
   - The passphrase is expanded into an AES-256-GCM key using PBKDF2-SHA256.  
     Iteration count depends on selected strength.
   - Metadata + file are encrypted into ciphertext.

3. **PNG container**
   - If a cover image is provided, it is converted to PNG. Otherwise, a black placeholder PNG is generated.
   - The encrypted payload is appended to the end of the PNG file.
   - A trailer containing payload length and a random marker ensures integrity.

4. **Decryption**
   - Blackout locates the trailer, extracts the encrypted payload, and checks the marker.
   - Using the passphrase, the same key is derived.
   - The ciphertext is decrypted back into metadata + file.
   - The original file is reconstructed with its stored filename and type.

5. **Vaults**
   - Every successful encryption can be logged into a **Vault** (encrypted logbook).
   - Each vault is AES-256-GCM encrypted with its own salt.
   - Vaults can only be unlocked using the App Lock passcode.
   - Logs contain metadata only (filename, size, output name, KDF, notes) — never the actual file or passphrase.

This design ensures:
- **Confidentiality**: without the passphrase, the data inside the PNG is unreadable.
- **Integrity**: GCM mode detects tampering.
- **Stealth**: PNG files look like normal images unless opened in Blackout.
- **Isolation**: Vaults protect history with additional encryption.

## Security Notes

- Blackout uses AES-256-GCM for authenticated encryption.  
- Keys are derived with PBKDF2-SHA256, configurable iteration counts.  
- Vaults are encrypted per-vault with independent salts.  
- Passcodes and encryption keys are never stored; keys exist only in memory until you reload or lock the app.  
- Output filenames never reveal the original file unless you explicitly set a stored name.

## Limitations

- Do not share PNGs through apps that compress images (e.g., some messengers) — this will corrupt the file.  
- Instead, share as a **Document** or use the raw `.blackout` container export.  
- Clearing browser storage will remove your vaults permanently.  
- Large files are capped (default 100 MB) for browser performance.

## Future Improvements

- **Nested encryption layers**: ability to re-encrypt an already encrypted PNG or container with a new password (onion-style).  
- **Extended export options**: support exporting in multiple formats:  
  - `.blackout` raw container  
  - `.zip` auto-wrapped version  
- **Share-safe helper**: detect the platform (WhatsApp, Telegram, etc.) and suggest the safest way to share (as document vs. image).  
- **Vault backup/restore**: allow exporting an encrypted `.vault` file for backup and re-importing it.  
- **Integrity checks**: embed and verify file hash to ensure corruption is detected before decrypt.  
- **Passcode migration**: ability to re-key vaults if the App Lock passcode changes.  
- **Larger file support**: investigate streaming encryption to allow files beyond the current size cap.

## License

This project is released under the MIT License.
