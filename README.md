# Haven Password Manager

A lightweight Chrome Manifest V3 extension scaffold for a local, encrypted password vault.

## Load in Chrome

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select this project folder.
4. Pin Haven from the Extensions menu, then open it.

## What it does

- Creates a vault protected by a master password (minimum 10 characters).
- Encrypts the complete vault with AES-256-GCM. A key is derived using PBKDF2-SHA-256 with a per-vault random salt and 310,000 iterations; each save uses a fresh random AES-GCM nonce.
- Stores only the encrypted vault in `chrome.storage.local`.
- Adds, edits, searches, copies, and deletes login entries; generates cryptographically random passwords locally with configurable length and character types.
- Fills visible login fields on the active website tab when you choose **Fill login**. Haven uses temporary `activeTab` access, never submits the form, and does not run a content script in the background.
- Keeps decrypted data only in the popup's memory. Closing the popup ends that in-memory session.

## Important limitations

This is a starter extension, not an audited or production-ready password manager. The master password cannot be recovered, and the vault is not synced or backed up. Import/export, breach monitoring, and cross-device sync are not included. Autofill is explicitly user-triggered and best-effort: it may not recognize custom or cross-origin login forms, and it never submits them. Do not use it as the sole home for important credentials until it has received a security review and a backup/recovery design.

The popup deliberately does not request host permissions or communicate with a server, and uses system fonts so the interface works offline.
