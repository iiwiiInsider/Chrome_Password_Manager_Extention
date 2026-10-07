"use strict";

importScripts("session-store.js");

const VAULT_KEY = "havenEncryptedVault";
const PREFERENCES_KEY = "havenPreferences";
const AUTO_LOCK_ALARM = "haven-auto-lock";
const decoder = new TextDecoder();

function decodeBase64(value) {
  return Uint8Array.from(atob(value), char => char.charCodeAt(0));
}

async function decryptVault(key, stored) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decodeBase64(stored.iv) },
    key,
    decodeBase64(stored.ciphertext)
  );
  const entries = JSON.parse(decoder.decode(plaintext));
  if (!Array.isArray(entries)) throw new Error("Encrypted vault data is invalid.");
  return entries;
}

async function getPreferences() {
  const result = await chrome.storage.local.get(PREFERENCES_KEY);
  const preferences = result[PREFERENCES_KEY] || {};
  return {
    autoLockMinutes: [1, 5, 15, 30].includes(preferences.autoLockMinutes)
      ? preferences.autoLockMinutes
      : 5,
    rememberUnlock: preferences.rememberUnlock !== false,
    enabledOrigins: Array.isArray(preferences.enabledOrigins)
      ? preferences.enabledOrigins.filter(origin => typeof origin === "string")
      : []
  };
}

async function scheduleLock() {
  const session = await HavenSessionStore.get();
  if (!session) {
    await chrome.alarms.clear(AUTO_LOCK_ALARM);
    return;
  }
  const { autoLockMinutes } = await getPreferences();
  const dueAt = session.lastActivity + autoLockMinutes * 60 * 1000;
  if (dueAt <= Date.now()) {
    await lockSession();
    return;
  }
  await chrome.alarms.create(AUTO_LOCK_ALARM, { when: dueAt });
}

async function lockSession() {
  await HavenSessionStore.clear();
  await chrome.alarms.clear(AUTO_LOCK_ALARM);
  const tabs = await chrome.tabs.query({});
  await Promise.all(tabs.map(tab => {
    if (!tab.id) return Promise.resolve();
    return chrome.tabs.sendMessage(tab.id, { type: "haven-vault-locked" }).catch(() => {});
  }));
  await chrome.runtime.sendMessage({ type: "haven-session-expired" })
    .catch(() => {});
}

function normalizeOrigin(value) {
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol)) return null;
    return url.origin;
  } catch {
    return null;
  }
}

function permissionPattern(origin) {
  const url = new URL(origin);
  return `${url.protocol}//${url.hostname}/*`;
}

async function getSiteEntries(tab) {
  const origin = normalizeOrigin(tab.url || "");
  if (!origin) return [];
  const preferences = await getPreferences();
  if (!preferences.enabledOrigins.includes(origin)) return [];
  const hasPermission = await chrome.permissions.contains({ origins: [permissionPattern(origin)] });
  if (!hasPermission) return [];
  const session = await HavenSessionStore.get();
  if (!session) return [];
  if (Date.now() - session.lastActivity >= preferences.autoLockMinutes * 60 * 1000) {
    await lockSession();
    return [];
  }
  const stored = (await chrome.storage.local.get(VAULT_KEY))[VAULT_KEY];
  if (!stored) return [];
  const entries = await decryptVault(session.key, stored);
  return entries
    .filter(entry => entry.url && normalizeOrigin(entry.url.includes("://") ? entry.url : `https://${entry.url}`) === origin)
    .map(({ id, title, username }) => ({ id, title, username }));
}

async function injectSuggestions(tabId) {
  const tabInfo = await chrome.tabs.get(tabId).catch(() => null);
  if (!tabInfo?.url || !/^https?:\/\//i.test(tabInfo.url)) return;
  const entries = await getSiteEntries(tabInfo);
  if (!entries.length) {
    await chrome.tabs.sendMessage(tabId, {
      type: "haven-update-suggestions",
      entries: []
    }).catch(() => {});
    return;
  }
  await chrome.scripting.executeScript({
    target: { tabId },
    func: showLoginSuggestions,
    args: [entries]
  }).catch(error => {
    console.warn(`Could not show Haven autofill suggestions on ${normalizeOrigin(tabInfo.url)}.`, error);
  });
}

function showLoginSuggestions(entries) {
  if (globalThis.havenSuggestionState) {
    globalThis.havenSuggestionState.update(entries);
    return;
  }
  const host = document.createElement("div");
  host.id = `haven-${crypto.randomUUID()}`;
  host.style.cssText = "all:initial;position:fixed;z-index:2147483647;display:none";
  const shadow = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = ":host{all:initial;font-family:system-ui,-apple-system,'Segoe UI',sans-serif}.panel{min-width:220px;max-width:300px;padding:10px;background:#fff;border:1px solid #e6e5ee;border-radius:12px;box-shadow:0 8px 30px #16152c30;color:#28283a}.heading{padding:2px 7px 8px;color:#77778a;font-size:11px;font-weight:650}.item{display:block;width:100%;padding:8px 9px;border:0;border-radius:8px;background:#fff;color:#272638;text-align:left;cursor:pointer}.item:hover,.item:focus{background:#f1efff;outline:none}.title{display:block;font-size:12px;font-weight:650}.username{display:block;margin-top:3px;color:#77778a;font-size:10px}.status{padding:4px 7px 0;color:#6c5ad9;font-size:10px}";
  const panel = document.createElement("div");
  panel.className = "panel";
  const heading = document.createElement("div");
  heading.className = "heading";
  heading.textContent = "Fill with Haven";
  const status = document.createElement("div");
  status.className = "status";
  let activeField = null;
  let currentEntries = [];
  const controller = new AbortController();

  function fillFields(username, password, field) {
    const form = field?.form;
    const passwordInputs = [...(form || document).querySelectorAll('input[type="password"]')]
      .filter(input => !input.disabled && !input.readOnly && input.getClientRects().length);
    const passwordInput = passwordInputs.find(input => input === field) || passwordInputs[0];
    if (!passwordInput) {
      status.textContent = "No password field found.";
      return;
    }
    const scope = passwordInput.form || document;
    const usernameInput = [...scope.querySelectorAll("input")]
      .filter(input => !input.disabled && !input.readOnly && input !== passwordInput &&
        ["text", "email", "tel"].includes(input.type) && input.getClientRects().length)
      .sort((a, b) => {
        const score = input => /username|login|email/i.test(
          `${input.autocomplete} ${input.name} ${input.id} ${input.getAttribute("aria-label") || ""}`
        ) ? 0 : 1;
        return score(a) - score(b);
      })[0];
    const setValue = (input, value) => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
      setter.call(input, value);
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
    };
    if (usernameInput && username) setValue(usernameInput, username);
    setValue(passwordInput, password);
    passwordInput.focus();
  }

  function render() {
    panel.replaceChildren(heading);
    for (const entry of currentEntries) {
      const button = document.createElement("button");
      button.className = "item";
      button.type = "button";
      const title = document.createElement("span");
      title.className = "title";
      title.textContent = entry.title;
      button.append(title);
      if (entry.username) {
        const username = document.createElement("span");
        username.className = "username";
        username.textContent = entry.username;
        button.append(username);
      }
      button.addEventListener("click", async () => {
        status.textContent = "Filling login…";
        const response = await chrome.runtime.sendMessage({
          type: "haven-get-credentials",
          entryId: entry.id
        }).catch(() => null);
        if (!response?.ok) {
          status.textContent = response?.error || "Unlock Haven and try again.";
          return;
        }
        fillFields(response.username, response.password, activeField);
        status.textContent = "Filled — review before signing in.";
      });
      panel.append(button);
    }
    panel.append(status);
  }

  function update(nextEntries) {
    currentEntries = Array.isArray(nextEntries) ? nextEntries : [];
    render();
    host.style.display = currentEntries.length && activeField?.matches(":focus") ? "block" : "none";
  }
  shadow.append(style, panel);
  document.documentElement.append(host);

  function position() {
    if (!activeField?.isConnected) return;
    const bounds = activeField.getBoundingClientRect();
    host.style.left = `${Math.max(8, Math.min(bounds.left, innerWidth - 310))}px`;
    host.style.top = `${Math.min(bounds.bottom + 6, innerHeight - 180)}px`;
  }

  const onMessage = message => {
    if (message?.type === "haven-vault-locked" ||
        (message?.type === "haven-origin-disabled" && message.origin === location.origin)) {
      host.remove();
      controller.abort();
      chrome.runtime.onMessage.removeListener(onMessage);
      delete globalThis.havenSuggestionState;
    } else if (message?.type === "haven-update-suggestions") {
      update(message.entries);
    }
  };
  globalThis.havenSuggestionState = { update };
  update(entries);
  document.addEventListener("focusin", event => {
    const field = event.target;
    if (!(field instanceof HTMLInputElement) || field.disabled || field.readOnly ||
        !["password", "text", "email", "tel"].includes(field.type)) return;
    activeField = field;
    position();
    host.style.display = "block";
  }, { capture: true, signal: controller.signal });
  document.addEventListener("focusout", event => {
    if (host.contains(event.relatedTarget) || shadow.activeElement) return;
    setTimeout(() => {
      if (!host.matches(":hover")) host.style.display = "none";
    }, 150);
  }, { capture: true, signal: controller.signal });
  window.addEventListener("resize", position, { signal: controller.signal });
  window.addEventListener("scroll", position, { capture: true, signal: controller.signal });
  chrome.runtime.onMessage.addListener(onMessage);
  if (document.activeElement instanceof HTMLInputElement) {
    document.activeElement.dispatchEvent(new FocusEvent("focusin", { bubbles: true }));
  }
}

chrome.runtime.onConnect.addListener(port => {
  if (port.name !== "haven-popup-session") return;
  port.onMessage.addListener(() => {});
  port.onDisconnect.addListener(() => {
    void getPreferences()
      .then(preferences => preferences.rememberUnlock ? undefined : lockSession())
      .catch(error => console.error("Couldn't apply the popup-close vault setting.", error));
  });
});

chrome.runtime.onStartup.addListener(() => {
  void lockSession().catch(error => console.error("Couldn't clear Haven's session at browser startup.", error));
});

chrome.runtime.onInstalled.addListener(() => {
  void lockSession().catch(error => console.error("Couldn't clear Haven's session after installation.", error));
});

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === AUTO_LOCK_ALARM) {
    void scheduleLock().catch(error => console.error("Couldn't apply Haven's inactivity lock.", error));
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "complete") {
    void injectSuggestions(tabId).catch(error => {
      console.error(`Couldn't check for Haven logins on tab ${tabId}.`, error);
    });
  }
});

async function refreshEnabledTabs() {
  const preferences = await getPreferences();
  for (const origin of preferences.enabledOrigins) {
    const tabs = await chrome.tabs.query({ url: permissionPattern(origin) });
    await Promise.all(tabs.map(tab => tab.id ? injectSuggestions(tab.id) : Promise.resolve()));
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "haven-session-activity") {
    void (async () => {
      const touched = await HavenSessionStore.touch(Date.now());
      if (touched) await scheduleLock();
      sendResponse({ ok: true, touched });
    })().catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }
  if (message?.type === "haven-session-started") {
    void (async () => {
      const session = await HavenSessionStore.get();
      if (!session) throw new Error("Unlocked session key was not saved.");
      await HavenSessionStore.save(session.key, Date.now());
      await scheduleLock();
      const tabs = await chrome.tabs.query({});
      await Promise.all(tabs.map(tab => tab.id ? injectSuggestions(tab.id) : Promise.resolve()));
      sendResponse({ ok: true });
    })().catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }
  if (message?.type === "haven-session-locked") {
    void lockSession()
      .then(() => sendResponse({ ok: true }))
      .catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }
  if (message?.type === "haven-preferences-changed") {
    void Promise.all([scheduleLock(), refreshEnabledTabs()])
      .then(() => sendResponse({ ok: true }))
      .catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }
  if (message?.type === "haven-refresh-autofill" && Number.isInteger(message.tabId)) {
    void injectSuggestions(message.tabId)
      .then(() => sendResponse({ ok: true }))
      .catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }
  if (message?.type === "haven-vault-changed") {
    void refreshEnabledTabs()
      .then(() => sendResponse({ ok: true }))
      .catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }
  if (message?.type === "haven-disable-origin") {
    void (async () => {
      const origin = normalizeOrigin(message.origin || "");
      if (!origin) throw new Error("Website address is invalid.");
      const tabs = await chrome.tabs.query({});
      await Promise.all(tabs.map(tab => tab.id
        ? chrome.tabs.sendMessage(tab.id, { type: "haven-origin-disabled", origin }).catch(() => {})
        : Promise.resolve()));
      sendResponse({ ok: true });
    })().catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }
  if (message?.type === "haven-get-credentials") {
    void (async () => {
      const origin = normalizeOrigin(sender.tab?.url || "");
      const preferences = await getPreferences();
      if (!origin || !preferences.enabledOrigins.includes(origin) ||
          !await chrome.permissions.contains({ origins: [permissionPattern(origin)] })) {
        throw new Error("Haven does not have permission for this site.");
      }
      const session = await HavenSessionStore.get();
      if (!session || Date.now() - session.lastActivity >= preferences.autoLockMinutes * 60 * 1000) {
        await lockSession();
        throw new Error("Unlock Haven to fill this login.");
      }
      const stored = (await chrome.storage.local.get(VAULT_KEY))[VAULT_KEY];
      if (!stored) throw new Error("The encrypted vault could not be found.");
      const entries = await decryptVault(session.key, stored);
      const entry = entries.find(item => item.id === message.entryId &&
        normalizeOrigin(item.url?.includes("://") ? item.url : `https://${item.url}`) === origin);
      if (!entry) throw new Error("This login is not saved for this website.");
      await HavenSessionStore.touch(Date.now());
      await scheduleLock();
      sendResponse({ ok: true, username: entry.username, password: entry.password });
    })().catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }
  return false;
});

void scheduleLock().catch(error => console.error("Couldn't schedule Haven's inactivity lock.", error));
