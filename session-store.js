"use strict";

globalThis.HavenSessionStore = (() => {
  const DATABASE_NAME = "havenSession";
  const STORE_NAME = "state";
  const SESSION_KEY = "unlocked";

  function openDatabase() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DATABASE_NAME, 1);
      request.onupgradeneeded = () => request.result.createObjectStore(STORE_NAME);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async function transaction(mode, callback) {
    const database = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = database.transaction(STORE_NAME, mode);
      const store = tx.objectStore(STORE_NAME);
      let result;
      try {
        result = callback(store);
      } catch (error) {
        database.close();
        reject(error);
        return;
      }
      tx.oncomplete = () => {
        database.close();
        resolve(result);
      };
      tx.onerror = () => {
        database.close();
        reject(tx.error);
      };
      tx.onabort = () => {
        database.close();
        reject(tx.error || new Error("Session storage transaction was aborted."));
      };
    });
  }

  async function get() {
    const database = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = database.transaction(STORE_NAME, "readonly");
      const request = tx.objectStore(STORE_NAME).get(SESSION_KEY);
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
      tx.oncomplete = () => database.close();
      tx.onerror = () => {
        database.close();
        reject(tx.error);
      };
    });
  }

  function save(key, lastActivity) {
    return transaction("readwrite", store => store.put({ key, lastActivity }, SESSION_KEY));
  }

  async function touch(lastActivity) {
    const session = await get();
    if (!session) return false;
    await save(session.key, lastActivity);
    return true;
  }

  function clear() {
    return transaction("readwrite", store => store.delete(SESSION_KEY));
  }

  return { get, save, touch, clear };
})();
