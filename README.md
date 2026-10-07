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
- Fills visible login fields on the active website tab when you choose **Fill login**. For inline suggestions, Haven requests optional permission separately for each website you enable. It never submits the form or requests website access at install.
- Offers configurable inactivity lock and password-generator defaults in Settings. You can choose whether closing the popup keeps the vault unlocked until its timeout; locking clears the session key from extension IndexedDB and removes any open-page suggestions. Browser startup always locks the vault.
- Keeps the vault encryption key non-extractable in extension IndexedDB between popup openings until timeout or manual lock. This is less secure than lock-on-close, so only use this option on a trusted device and Chrome profile.
- Offers optional per-website autofill permission. When enabled for a saved website, focusing a login field shows a Haven suggestion; choosing it fills the login but never submits the form. Permissions can be removed in a login's details or Settings.

## Important limitations

This is a starter extension, not an audited or production-ready password manager. The master password cannot be recovered, and the vault is not synced or backed up. Import/export, breach monitoring, and cross-device sync are not included. Autofill is best-effort: it may not recognize custom or cross-origin login forms, and it never submits them. Do not use it as the sole home for important credentials until it has received a security review and a backup/recovery design.

Haven does not communicate with a server and uses system fonts so the interface works offline. Optional website access is requested only after you choose **Enable site** for a saved login; remove it from the login details or Settings.
