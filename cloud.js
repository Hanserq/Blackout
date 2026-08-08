/* Blackout Cloud Integration Module — 100% Client-Side Cloud Sync & Backup */
'use strict';

window.BlackoutCloud = (function () {

  // Default configuration for client-side OAuth
  const CONFIG = {
    vaultFolderName: 'Blackout Vault',
    googleClientId: '', // Optional user-provided or app Client ID
    oneDriveClientId: ''
  };

  /**
   * Save an encrypted payload (Uint8Array/ArrayBuffer) to local system cloud folder
   * (Google Drive desktop, iCloud Drive, OneDrive desktop synced folders) via File System Access API.
   */
  async function saveToSystemCloud(buffer, filename, mimeType, contextNote) {
    if (!('showSaveFilePicker' in window)) {
      // Fallback for browsers without File System Access API (trigger standard download with context sidecar if note provided)
      downloadFileWithContext(buffer, filename, mimeType, contextNote);
      return { success: true, method: 'download', filename: filename };
    }

    try {
      const opts = {
        suggestedName: filename,
        types: [{
          description: 'Blackout Encrypted Artifact',
          accept: { [mimeType || 'application/octet-stream']: ['.blackout', '.png'] }
        }]
      };
      const handle = await window.showSaveFilePicker(opts);
      const writable = await handle.createWritable();
      await writable.write(buffer);
      await writable.close();

      // If a context note was provided, save a companion metadata sidecar file
      if (contextNote && contextNote.trim()) {
        try {
          const metaName = filename + '.context.txt';
          const metaOpts = {
            suggestedName: metaName,
            types: [{ description: 'Blackout Context Note', accept: { 'text/plain': ['.txt'] } }]
          };
          const metaHandle = await window.showSaveFilePicker(metaOpts);
          const metaWritable = await metaHandle.createWritable();
          await metaWritable.write(new TextEncoder().encode(
            '=== BLACKOUT CONTEXT NOTE ===\n' +
            'File: ' + filename + '\n' +
            'Date: ' + new Date().toISOString() + '\n\n' +
            'Context / Secret Hint:\n' + contextNote.trim() + '\n'
          ));
          await metaWritable.close();
        } catch (e) {
          /* user skipped companion note save */
        }
      }

      return { success: true, method: 'filesystem', filename: handle.name };
    } catch (err) {
      if (err.name === 'AbortError') return { canceled: true };
      throw err;
    }
  }

  /**
   * Browser file download fallback including optional text sidecar for context note.
   */
  function downloadFileWithContext(buffer, filename, mimeType, contextNote) {
    const blob = new Blob([buffer], { type: mimeType || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);

    if (contextNote && contextNote.trim()) {
      const metaBlob = new Blob([
        '=== BLACKOUT CONTEXT NOTE ===\n' +
        'File: ' + filename + '\n' +
        'Date: ' + new Date().toISOString() + '\n\n' +
        'Context / Secret Hint:\n' + contextNote.trim() + '\n'
      ], { type: 'text/plain' });
      const metaUrl = URL.createObjectURL(metaBlob);
      const metaA = document.createElement('a');
      metaA.href = metaUrl;
      metaA.download = filename + '.context.txt';
      document.body.appendChild(metaA);
      metaA.click();
      metaA.remove();
      setTimeout(() => URL.revokeObjectURL(metaUrl), 10000);
    }
  }

  /**
   * Import file from local system cloud folder via File System Access API
   */
  async function importFromSystemCloud() {
    if (!('showOpenFilePicker' in window)) {
      throw new Error('File System Access API is not supported in this browser. Use standard file selection.');
    }
    const [handle] = await window.showOpenFilePicker({
      multiple: false,
      types: [{
        description: 'Blackout Files & Camo PNGs',
        accept: {
          'application/octet-stream': ['.blackout'],
          'image/png': ['.png']
        }
      }]
    });
    const file = await handle.getFile();
    return file;
  }

  /**
   * Client-side Google Drive Direct Upload (REST API v3)
   * Uploads file to "Blackout Vault" folder in user's personal Google Drive with description metadata.
   */
  async function uploadToGoogleDrive(accessToken, buffer, filename, mimeType, contextNote) {
    if (!accessToken) throw new Error('Google Drive Access Token required.');

    // 1. Find or create "Blackout Vault" folder
    let folderId = await getOrCreateGoogleFolder(accessToken, CONFIG.vaultFolderName);

    // 2. Multipart upload (Metadata + Binary Data)
    const metadata = {
      name: filename,
      description: contextNote ? ('[Blackout Vault Note]: ' + contextNote) : 'Encrypted with Blackout Steganography',
      parents: [folderId]
    };

    const boundary = '-------314159265358979323846';
    const delimiter = "\r\n--" + boundary + "\r\n";
    const close_delim = "\r\n--" + boundary + "--";

    const contentType = mimeType || 'application/octet-stream';
    const metadataBlob = new Blob([JSON.stringify(metadata)], { type: 'application/json' });
    const payloadBlob = new Blob([buffer], { type: contentType });

    const postBody = new Blob([
      delimiter,
      'Content-Type: application/json\r\n\r\n',
      metadataBlob,
      delimiter,
      'Content-Type: ' + contentType + '\r\n\r\n',
      payloadBlob,
      close_delim
    ]);

    const res = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + accessToken,
        'Content-Type': 'multipart/related; boundary=' + boundary
      },
      body: postBody
    });

    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      throw new Error('Google Drive upload failed: ' + (errJson.error && errJson.error.message || res.statusText));
    }

    const data = await res.json();
    return { success: true, fileId: data.id, name: data.name, folder: CONFIG.vaultFolderName };
  }

  async function getOrCreateGoogleFolder(accessToken, folderName) {
    // Query existing folder
    const q = encodeURIComponent(`name = '${folderName}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false`);
    const checkRes = await fetch(`https://www.googleapis.com/drive/v3/files?q=${q}`, {
      headers: { 'Authorization': 'Bearer ' + accessToken }
    });
    if (checkRes.ok) {
      const data = await checkRes.json();
      if (data.files && data.files.length > 0) {
        return data.files[0].id;
      }
    }

    // Create folder if not found
    const createRes = await fetch('https://www.googleapis.com/drive/v3/files', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + accessToken,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        name: folderName,
        mimeType: 'application/vnd.google-apps.folder'
      })
    });
    if (!createRes.ok) throw new Error('Failed to create Blackout Vault folder in Google Drive.');
    const folderData = await createRes.json();
    return folderData.id;
  }

  let _gTokenClient = null;
  let _cachedGoogleToken = null;

  function getCachedGoogleToken() { return _cachedGoogleToken; }

  function requestGoogleOAuthToken(customClientId, onSuccess, onError) {
    if (!window.google || !window.google.accounts || !window.google.accounts.oauth2) {
      if (onError) onError('Google Identity Services library not loaded. Check internet connection.');
      return;
    }
    const clientId = (customClientId || '').trim() || CONFIG.googleClientId;
    if (!clientId) {
      if (onError) onError('Please enter your Google OAuth Client ID under Advanced settings.');
      return;
    }
    try {
      _gTokenClient = window.google.accounts.oauth2.initTokenClient({
        client_id: clientId,
        scope: 'https://www.googleapis.com/auth/drive.file',
        callback: (resp) => {
          if (resp.error) {
            if (onError) onError('Google Auth error: ' + resp.error);
            return;
          }
          _cachedGoogleToken = resp.access_token;
          if (onSuccess) onSuccess(_cachedGoogleToken);
        }
      });
      _gTokenClient.requestAccessToken({ prompt: '' });
    } catch (e) {
      if (onError) onError('OAuth Popup error: ' + (e && e.message ? e.message : e));
    }
  }

  return {
    saveToSystemCloud,
    downloadFileWithContext,
    importFromSystemCloud,
    uploadToGoogleDrive,
    requestGoogleOAuthToken,
    getCachedGoogleToken,
    CONFIG
  };

})();

