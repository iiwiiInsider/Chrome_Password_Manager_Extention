"use strict";

const STORAGE_KEY = "havenEncryptedVault";
const PBKDF2_ITERATIONS = 310000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const app = document.querySelector("#app");
const toast = document.querySelector("#toast");

let vault = [];
let cryptoKey = null;
let vaultSalt = null;
let toastTimer = null;
let query = "";

const icons = {
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><path d="M12 14v3"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
  search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 4 4"/></svg>',
  copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg>',
  edit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m14 5 5 5M4 20l4.3-.9L19 8.4a2.1 2.1 0 0 0-3-3L5.3 16.1 4 20Z"/></svg>',
  close: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="m6 6 12 12M18 6 6 18"/></svg>'
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary);
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), char => char.charCodeAt(0));
}

function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptVault(key, items, salt) {
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(JSON.stringify(items))
  );
  return {
    version: 1,
    kdf: "PBKDF2-SHA-256",
    iterations: PBKDF2_ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  };
}

async function decryptVault(key, stored) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(stored.iv) },
    key,
    base64ToBytes(stored.ciphertext)
  );
  const parsed = JSON.parse(decoder.decode(plaintext));
  if (!Array.isArray(parsed)) throw new Error("Vault data is invalid.");
  return parsed;
}

async function persistVault() {
  const encrypted = await encryptVault(cryptoKey, vault, vaultSalt);
  await chrome.storage.local.set({ [STORAGE_KEY]: encrypted });
}

async function initialize() {
  try {
    if (!globalThis.crypto?.subtle || !globalThis.chrome?.storage?.local) {
      throw new Error("This extension needs Chrome's secure storage and Web Crypto APIs.");
    }
    const result = await chrome.storage.local.get(STORAGE_KEY);
    result[STORAGE_KEY] ? renderUnlock() : renderCreate();
  } catch (error) {
    app.innerHTML = `<section class="screen-center"><div class="brand"><span class="brand-mark">h</span><span class="brand-name">Haven</span></div><h1>Couldn't open Haven</h1><p class="intro">${escapeHtml(error.message)}</p></section>`;
  }
}

function brand() {
  return '<div class="brand"><span class="brand-mark" aria-hidden="true">h</span><div><div class="brand-name">haven</div><div class="brand-caption">your private vault</div></div></div>';
}

function renderCreate(error = "") {
  app.innerHTML = `
    <section class="screen-center">
      ${brand()}
      <div class="lock-art" aria-hidden="true">${icons.lock}</div>
      <h1>Create your vault</h1>
      <p class="intro">One strong master password protects everything you save here.</p>
      <form class="auth-form" id="create-form">
        <div class="field"><label for="master-password">Master password</label><div class="input-wrap"><input class="input with-action" id="master-password" name="password" type="password" autocomplete="new-password" minlength="10" required autofocus placeholder="At least 10 characters"><button class="input-action" type="button" data-toggle="master-password">Show</button></div></div>
        <div class="field"><label for="confirm-password">Confirm master password</label><input class="input" id="confirm-password" name="confirm" type="password" autocomplete="new-password" required placeholder="Enter it again"></div>
        <div class="error" role="alert">${escapeHtml(error)}</div>
        <button class="button full" type="submit">Create secure vault</button>
      </form>
      <p class="hint">Your vault is encrypted on this device. There is no password reset — remember your master password.</p>
    </section>`;

  app.querySelector("#create-form").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const password = form.elements.password.value;
    const confirm = form.elements.confirm.value;
    if (password.length < 10) return setFormError(form, "Use at least 10 characters for your master password.");
    if (password !== confirm) return setFormError(form, "Those passwords don't match.");
    const submit = form.querySelector('[type="submit"]');
    submit.disabled = true;
    submit.textContent = "Creating vault…";
    try {
      vaultSalt = randomBytes(16);
      cryptoKey = await deriveKey(password, vaultSalt);
      vault = [];
      await persistVault();
      renderVault();
    } catch (error) {
      submit.disabled = false;
      submit.textContent = "Create secure vault";
      setFormError(form, `Couldn't create the vault: ${error.message}`);
    }
  });
}

function renderUnlock(error = "") {
  app.innerHTML = `
    <section class="screen-center">
      ${brand()}
      <div class="lock-art" aria-hidden="true">${icons.lock}</div>
      <h1>Welcome back</h1>
      <p class="intro">Unlock your encrypted vault to get to your passwords.</p>
      <form class="auth-form" id="unlock-form">
        <div class="field"><label for="master-password">Master password</label><div class="input-wrap"><input class="input with-action" id="master-password" name="password" type="password" autocomplete="current-password" required autofocus placeholder="Enter your master password"><button class="input-action" type="button" data-toggle="master-password">Show</button></div></div>
        <div class="error" role="alert">${escapeHtml(error)}</div>
        <button class="button full" type="submit">Unlock vault</button>
      </form>
      <p class="hint">Your vault is only decrypted in memory while this popup is open.</p>
    </section>`;

  app.querySelector("#unlock-form").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector('[type="submit"]');
    submit.disabled = true;
    submit.textContent = "Unlocking…";
    try {
      const stored = (await chrome.storage.local.get(STORAGE_KEY))[STORAGE_KEY];
      if (!stored || stored.version !== 1 || stored.kdf !== "PBKDF2-SHA-256" ||
          stored.iterations !== PBKDF2_ITERATIONS || !stored.salt || !stored.iv || !stored.ciphertext) {
        throw new Error("The saved vault format is not supported.");
      }
      const key = await deriveKey(form.elements.password.value, base64ToBytes(stored.salt));
      vault = await decryptVault(key, stored);
      cryptoKey = key;
      vaultSalt = base64ToBytes(stored.salt);
      renderVault();
    } catch (error) {
      submit.disabled = false;
      submit.textContent = "Unlock vault";
      const message = error.name === "OperationError"
        ? "That password didn't unlock this vault. Try again."
        : `Couldn't open the vault: ${error.message}`;
      setFormError(form, message);
      form.elements.password.focus();
    }
  });
}

function setFormError(form, message) {
  const error = form.querySelector('[role="alert"]');
  if (error) error.textContent = message;
}

function renderVault() {
  const filtered = vault
    .filter(item => `${item.title} ${item.username} ${item.url}`.toLowerCase().includes(query.toLowerCase()))
    .sort((a, b) => a.title.localeCompare(b.title));
  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">${brand()}<div class="top-actions"><button class="icon-button" type="button" data-action="lock" aria-label="Lock vault" title="Lock vault">${icons.lock}</button></div></header>
      <section class="content">
        <div class="welcome-row"><div><h1>Your passwords</h1><p>${vault.length} ${vault.length === 1 ? "login" : "logins"} saved securely</p></div><button class="button add-button" type="button" data-action="add">${icons.plus} Add new</button></div>
        <div class="search-wrap">${icons.search}<input class="input search" type="search" placeholder="Search your vault" aria-label="Search your vault" value="${escapeHtml(query)}"></div>
        <div class="section-label"><span>${query ? "Search results" : "All logins"}</span><span>${filtered.length}</span></div>
        ${filtered.length ? `<div class="entry-list">${filtered.map(entryCard).join("")}</div>` : `<div class="empty-state"><div class="empty-icon" aria-hidden="true">✳</div><strong>${query ? "No matching logins" : "Your vault is ready"}</strong><p>${query ? "Try another search or check the spelling." : "Add your first login and keep it safely tucked away."}</p>${!query ? `<button class="button secondary add-button" type="button" data-action="add">${icons.plus} Add your first login</button>` : ""}</div>`}
      </section>
      <footer class="footer-note"><span>● Encrypted</span> on this device · Only you can unlock it</footer>
    </div>`;

  app.querySelector(".search").addEventListener("input", event => {
    query = event.target.value;
    const position = event.target.selectionStart;
    renderVault();
    const input = app.querySelector(".search");
    input.focus();
    input.setSelectionRange(position, position);
  });
}

function entryCard(entry) {
  const id = escapeHtml(entry.id);
  const title = escapeHtml(entry.title);
  const username = escapeHtml(entry.username || entry.url || "Login details");
  const initial = escapeHtml((entry.title || "?").trim().charAt(0));
  return `<article class="entry-card"><div class="entry-icon" aria-hidden="true">${initial}</div><div class="entry-info"><div class="entry-title">${title}</div><div class="entry-subtitle">${username}</div></div><div class="entry-actions"><button class="mini-button" type="button" data-action="copy" data-id="${id}" aria-label="Copy password for ${title}" title="Copy password">${icons.copy}</button><button class="mini-button" type="button" data-action="detail" data-id="${id}" aria-label="View ${title}" title="View details">•••</button></div></article>`;
}

function openEntryForm(entry = null) {
  const editing = Boolean(entry);
  const title = editing ? "Edit login" : "Add a login";
  app.insertAdjacentHTML("beforeend", `
    <div class="overlay" data-overlay>
      <section class="dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title">
        <header class="dialog-header"><div><h2 id="dialog-title">${title}</h2><p>Saved encrypted in your private vault</p></div><button class="icon-button close-button" type="button" data-action="close" aria-label="Close">${icons.close}</button></header>
        <form class="entry-form" id="entry-form">
          <input type="hidden" name="id" value="${escapeHtml(entry?.id || "")}">
          <div class="field"><label for="entry-title">Name</label><input class="input" id="entry-title" name="title" required maxlength="100" placeholder="e.g. Email, Banking" value="${escapeHtml(entry?.title || "")}"></div>
          <div class="form-row">
            <div class="field"><label for="entry-username">Username</label><input class="input" id="entry-username" name="username" maxlength="200" autocomplete="off" placeholder="name@example.com" value="${escapeHtml(entry?.username || "")}"></div>
            <div class="field"><label for="entry-url">Website</label><input class="input" id="entry-url" name="url" maxlength="500" inputmode="url" placeholder="example.com" value="${escapeHtml(entry?.url || "")}"></div>
          </div>
          <div class="field">
            <div class="password-tools"><label for="entry-password">Password</label><button class="button secondary" type="button" data-action="generate">✦ Generate</button></div>
            <input class="input" id="entry-password" name="password" type="password" autocomplete="new-password" required maxlength="500" placeholder="Enter or generate a password" value="${escapeHtml(entry?.password || "")}">
            <details class="generator-settings">
              <summary>Password options</summary>
              <div class="generator-panel">
                <label class="length-label" for="password-length">Length <output id="password-length-value">20</output></label>
                <input id="password-length" class="length-slider" type="range" min="8" max="64" value="20">
                <div class="character-options">
                  <label><input type="checkbox" name="charset" value="uppercase" checked> Uppercase</label>
                  <label><input type="checkbox" name="charset" value="lowercase" checked> Lowercase</label>
                  <label><input type="checkbox" name="charset" value="numbers" checked> Numbers</label>
                  <label><input type="checkbox" name="charset" value="symbols" checked> Symbols</label>
                </div>
              </div>
            </details>
          </div>
          <div class="field"><label for="entry-notes">Notes <span class="optional-label">(optional)</span></label><input class="input" id="entry-notes" name="notes" maxlength="1000" placeholder="Anything else to remember" value="${escapeHtml(entry?.notes || "")}"></div>
          <div class="form-error" role="alert"></div>
          <div class="dialog-actions"><button class="button ghost" type="button" data-action="close">Cancel</button><button class="button" type="submit">${editing ? "Save changes" : "Save login"}</button></div>
        </form>
      </section>
    </div>`);

  const form = app.querySelector("#entry-form");
  form.elements.title.focus();
  const lengthInput = form.querySelector("#password-length");
  const lengthOutput = form.querySelector("#password-length-value");
  lengthInput.addEventListener("input", () => {
    lengthOutput.value = lengthInput.value;
  });
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const data = new FormData(form);
    const item = {
      id: data.get("id") || crypto.randomUUID(),
      title: data.get("title").trim(),
      username: data.get("username").trim(),
      url: data.get("url").trim(),
      password: data.get("password"),
      notes: data.get("notes").trim()
    };
    if (!item.title || !item.password) {
      form.querySelector(".form-error").textContent = "A name and password are required.";
      return;
    }
    const button = form.querySelector('[type="submit"]');
    const previousVault = vault;
    button.disabled = true;
    try {
      vault = editing ? vault.map(old => old.id === item.id ? item : old) : [...vault, item];
      await persistVault();
      renderVault();
      showToast(editing ? "Login updated" : "Login saved");
    } catch (error) {
      vault = previousVault;
      button.disabled = false;
      form.querySelector(".form-error").textContent = `Couldn't save this login: ${error.message}`;
    }
  });
}

function openDetail(entry) {
  app.insertAdjacentHTML("beforeend", `
    <div class="overlay" data-overlay>
      <section class="dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title">
        <header class="dialog-header"><div><h2 id="dialog-title">${escapeHtml(entry.title)}</h2><p>Login details</p></div><button class="icon-button close-button" type="button" data-action="close" aria-label="Close">${icons.close}</button></header>
        <div class="entry-detail">
          ${detailField("Username", entry.username || "—")}
          ${detailField("Website", entry.url || "—")}
          ${detailField("Password", "••••••••••••")}
          ${entry.notes ? detailField("Notes", entry.notes) : ""}
        </div>
        <div class="detail-actions"><button class="button danger" type="button" data-action="delete" data-id="${escapeHtml(entry.id)}">Delete</button><div class="detail-actions-right"><button class="button secondary" type="button" data-action="autofill" data-id="${escapeHtml(entry.id)}">Fill login</button><button class="button secondary" type="button" data-action="copy" data-id="${escapeHtml(entry.id)}">Copy</button><button class="button" type="button" data-action="edit" data-id="${escapeHtml(entry.id)}">Edit</button></div></div>
      </section>
    </div>`);
}

function detailField(label, value) {
  return `<div class="detail-field"><div class="detail-label">${escapeHtml(label)}</div><div class="detail-value">${escapeHtml(value)}</div></div>`;
}

function secureRandomIndex(maxExclusive) {
  const range = 0x100000000;
  const limit = Math.floor(range / maxExclusive) * maxExclusive;
  const value = new Uint32Array(1);
  do {
    crypto.getRandomValues(value);
  } while (value[0] >= limit);
  return value[0] % maxExclusive;
}

function generatePassword(length, selectedSets) {
  const characterSets = {
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    numbers: "0123456789",
    symbols: "!@#$%^&*()-_=+[]{};:,.?"
  };
  const sets = selectedSets.map(name => characterSets[name]).filter(Boolean);
  if (sets.length === 0) throw new Error("Choose at least one character type.");
  if (length < sets.length) throw new Error("Password length must fit each selected character type.");

  const alphabet = [...new Set(sets.join(""))];
  const password = sets.map(set => set[secureRandomIndex(set.length)]);
  while (password.length < length) password.push(alphabet[secureRandomIndex(alphabet.length)]);
  for (let index = password.length - 1; index > 0; index--) {
    const swapIndex = secureRandomIndex(index + 1);
    [password[index], password[swapIndex]] = [password[swapIndex], password[index]];
  }
  return password.join("");
}

async function copyPassword(entry) {
  try {
    await navigator.clipboard.writeText(entry.password);
    showToast("Password copied to clipboard");
  } catch (error) {
    showToast(`Couldn't copy password: ${error.message}`);
  }
}

async function autofillLogin(entry) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !tab.url || !/^https?:\/\//i.test(tab.url)) {
      showToast("Open a website tab to fill this login");
      return;
    }
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: fillLoginFields,
      args: [entry.username, entry.password]
    });
    if (!result?.result?.passwordFilled) {
      showToast("No visible password field found on this page");
      return;
    }
    showToast(result.result.usernameFilled
      ? "Login filled — review it before signing in"
      : "Password filled — no username field found");
  } catch (error) {
    showToast(`Couldn't fill this page: ${error.message}`);
  }
}

function fillLoginFields(username, password) {
  const isVisible = element => {
    const style = getComputedStyle(element);
    return element.getClientRects().length > 0 &&
      style.visibility !== "hidden" && style.display !== "none";
  };
  const isUsable = element =>
    !element.disabled && !element.readOnly && isVisible(element);
  const passwordFields = [...document.querySelectorAll('input[type="password"]')]
    .filter(isUsable);
  if (!passwordFields.length) return { passwordFilled: false, usernameFilled: false };

  const activeForm = document.activeElement?.form;
  const passwordField = passwordFields.find(field => field.form && field.form === activeForm) ||
    passwordFields[0];
  const scope = passwordField.form || document;
  const fields = [...scope.querySelectorAll("input")]
    .filter(field => field.type !== "password" && isUsable(field));
  const usernameField = fields
    .filter(field => {
      const type = field.type.toLowerCase();
      return ["text", "email", "tel", "url"].includes(type);
    })
    .map((field, index) => {
      const hint = `${field.autocomplete} ${field.name} ${field.id} ${field.getAttribute("aria-label") || ""}`
        .toLowerCase();
      let score = index;
      if (/\busername\b|\blogin\b|\buser(name)?\b|\bemail\b/.test(hint)) score -= 100;
      if (field.autocomplete === "username") score -= 100;
      if (field.type === "email") score -= 5;
      return { field, score };
    })
    .sort((a, b) => a.score - b.score)[0]?.field;

  const setValue = (field, value) => {
    const setter = Object.getOwnPropertyDescriptor(
      field instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype,
      "value"
    )?.set;
    if (setter) setter.call(field, value);
    else field.value = value;
    field.dispatchEvent(new Event("input", { bubbles: true }));
    field.dispatchEvent(new Event("change", { bubbles: true }));
  };

  if (usernameField && username) setValue(usernameField, username);
  setValue(passwordField, password);
  passwordField.focus();
  return { passwordFilled: true, usernameFilled: Boolean(usernameField && username) };
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("visible"), 2200);
}

function lockVault() {
  vault = [];
  cryptoKey = null;
  vaultSalt = null;
  query = "";
  renderUnlock();
}

app.addEventListener("click", async event => {
  const actionButton = event.target.closest("[data-action]");
  if (!actionButton) {
    if (event.target.matches("[data-overlay]")) event.target.remove();
    return;
  }
  const action = actionButton.dataset.action;
  const entry = vault.find(item => item.id === actionButton.dataset.id);
  if (action === "add") openEntryForm();
  if (action === "lock") lockVault();
  if (action === "close") actionButton.closest("[data-overlay]")?.remove();
  if (action === "generate") {
    const input = app.querySelector("#entry-password");
    const form = app.querySelector("#entry-form");
    const selectedSets = [...form.querySelectorAll('input[name="charset"]:checked')]
      .map(option => option.value);
    try {
      input.value = generatePassword(Number(form.querySelector("#password-length").value), selectedSets);
    } catch (error) {
      form.querySelector(".form-error").textContent = error.message;
      return;
    }
    form.querySelector(".form-error").textContent = "";
    input.type = "text";
    input.focus();
    showToast("Secure password generated");
  }
  if (action === "copy" && entry) await copyPassword(entry);
  if (action === "autofill" && entry) await autofillLogin(entry);
  if (action === "detail" && entry) openDetail(entry);
  if (action === "edit" && entry) {
    actionButton.closest("[data-overlay]").remove();
    openEntryForm(entry);
  }
  if (action === "delete" && entry) {
    const previousVault = vault;
    vault = vault.filter(item => item.id !== entry.id);
    try {
      await persistVault();
      renderVault();
      showToast("Login deleted");
    } catch (error) {
      vault = previousVault;
      showToast(`Couldn't delete login: ${error.message}`);
    }
  }
});

app.addEventListener("click", event => {
  const toggle = event.target.closest("[data-toggle]");
  if (!toggle) return;
  const input = app.querySelector(`#${toggle.dataset.toggle}`);
  input.type = input.type === "password" ? "text" : "password";
  toggle.textContent = input.type === "password" ? "Show" : "Hide";
});

document.addEventListener("keydown", event => {
  if (event.key === "Escape") app.querySelector("[data-overlay]")?.remove();
});

initialize();
