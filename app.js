/* SecretDrop — client-side encrypted, self-destructing secrets.
 *
 * Security model:
 *  - Every secret is encrypted in the browser with a fresh random AES-256-GCM
 *    key. The plaintext never leaves the browser unencrypted.
 *  - The key lives ONLY in the URL fragment (#k=...). Fragments are never sent
 *    in HTTP requests, and this app never stores the key anywhere.
 *  - With a password, the data key is wrapped with a PBKDF2-derived key
 *    (250,000 iterations, SHA-256, random salt) and the key is NOT in the link.
 *  - The encrypted record lives on the SERVER (KVdb via window.KVStore, or a
 *    self-hosted backend when APP_CONFIG.apiBase is set), so a link works on
 *    any device. The server only ever receives ciphertext. Burning means
 *    deleting the server record.
 *  - "My secrets" is a LOCAL index (localStorage, metadata only: id,
 *    createdAt, expiryLabel) of secrets created in this browser — the server
 *    cannot list keys, so only secrets created here can be listed here.
 */
"use strict";

var FALLBACK_CONFIG = { bucket: "D6nggBKozgz4G6KNT1ha5A", prefix: "sd:", apiBase: "" };
if (typeof window !== "undefined" && window.KVStore && window.KVStore.configure) {
  window.KVStore.configure(window.APP_CONFIG || FALLBACK_CONFIG);
}
var PBKDF2_ITERATIONS = 250000;
var MAX_CHARS = 10000;
var INDEX_KEY = "secretdrop:my-index:v1";

/* ---------- tiny DOM helpers ---------- */
function $(id) { return document.getElementById(id); }
function show(el) { el.hidden = false; }
function hide(el) { el.hidden = true; }
function setError(el, message) {
  if (!message) { hide(el); el.textContent = ""; return; }
  el.textContent = message; show(el);
}

var toastTimer = null;
function toast(message) {
  var t = $("toast");
  t.textContent = message;
  show(t);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function () { hide(t); }, 3200);
}

/* ---------- base64url helpers ---------- */
function bufToB64url(buf) {
  var bytes = new Uint8Array(buf);
  var bin = "";
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBuf(str) {
  var b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function textToBuf(text) { return new TextEncoder().encode(text); }
function bufToText(buf) { return new TextDecoder().decode(buf); }
function randomBytes(n) {
  var b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
function newId() { return bufToB64url(randomBytes(9)); } // 12 URL-safe chars

/* ---------- WebCrypto helpers ---------- */
function cryptoAvailable() {
  return !!(window.crypto && crypto.subtle && window.isSecureContext !== false && crypto.subtle.generateKey);
}
function generateDataKey() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}
function exportRawKey(key) { return crypto.subtle.exportKey("raw", key); }
function importRawKey(rawBuf) {
  return crypto.subtle.importKey("raw", rawBuf, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
function encryptWithKey(key, plaintext) {
  var iv = randomBytes(12);
  return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, textToBuf(plaintext))
    .then(function (ct) { return { iv: bufToB64url(iv), data: bufToB64url(ct) }; });
}
function decryptWithKey(key, ivB64, dataB64) {
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(b64urlToBuf(ivB64)) },
    key, b64urlToBuf(dataB64)
  ).then(bufToText);
}
function derivePasswordKey(password, saltBuf) {
  return crypto.subtle.importKey("raw", textToBuf(password), "PBKDF2", false, ["deriveKey"])
    .then(function (base) {
      return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: saltBuf, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
        base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
      );
    });
}

/* ---------- server store (KVStore) + local metadata index ---------- */
function kv() { return window.KVStore; }

function saveRecord(rec) {
  // PUT the encrypted record under the secret id. Resolves true on success.
  return kv().put(rec.id, rec);
}
function loadRecord(id) {
  return kv().get(id).then(function (rec) {
    if (!rec || rec.v !== 1 || typeof rec.data !== "string") return null;
    return rec;
  });
}
function deleteRecord(id) {
  removeFromIndex(id);
  return kv().del(id);
}
function isExpired(rec) {
  return !!(rec.expiresAt && Date.now() > rec.expiresAt);
}

/* Local index: metadata ONLY (no ciphertext, no key) for secrets this
 * browser created, so "My secrets" can list them. The server cannot list
 * keys, so this list is honestly "created in this browser". */
var memoryIndex = [];
function loadIndex() {
  try {
    var raw = localStorage.getItem(INDEX_KEY);
    if (!raw) return [];
    var parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) { return memoryIndex.slice(); }
}
function saveIndex(entries) {
  memoryIndex = entries.slice();
  try { localStorage.setItem(INDEX_KEY, JSON.stringify(entries)); } catch (e) { /* keep in-memory copy */ }
}
function addToIndex(rec) {
  var entries = loadIndex().filter(function (e) { return e.id !== rec.id; });
  entries.unshift({
    id: rec.id, createdAt: rec.createdAt, expiresAt: rec.expiresAt,
    expiryLabel: rec.expiryLabel, hasPassword: !!rec.hasPassword,
    maxViews: rec.maxViews || null, views: rec.views || 0
  });
  saveIndex(entries);
}
function removeFromIndex(id) {
  saveIndex(loadIndex().filter(function (e) { return e.id !== id; }));
}
function updateIndexViews(id, views) {
  var entries = loadIndex();
  var changed = false;
  entries.forEach(function (e) { if (e.id === id) { e.views = views; changed = true; } });
  if (changed) saveIndex(entries);
}
function pruneExpired() {
  // Delete expired records from the server, using the local index.
  var now = Date.now();
  var entries = loadIndex();
  var expired = entries.filter(function (e) { return e.expiresAt && now > e.expiresAt; });
  if (!expired.length) return Promise.resolve();
  return Promise.all(expired.map(function (e) { return kv().del(e.id); }))
    .then(function () {
      saveIndex(loadIndex().filter(function (e) { return !(e.expiresAt && Date.now() > e.expiresAt); }));
    })
    .catch(function () { /* server unreachable — keep the index, retry later */ });
}

/* ---------- formatting ---------- */
function expiryLabelFor(choice) {
  if (choice === "one-view") return "After 1 view";
  if (choice === "1h") return "1 hour";
  if (choice === "24h") return "24 hours";
  if (choice === "7d") return "7 days";
  return choice;
}
function expiryMsFor(choice) {
  if (choice === "1h") return 60 * 60 * 1000;
  if (choice === "24h") return 24 * 60 * 60 * 1000;
  if (choice === "7d") return 7 * 24 * 60 * 60 * 1000;
  return null; // one-view: no timer
}
function formatDate(ts) {
  return new Date(ts).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"
  });
}
function timeLeft(ts) {
  var ms = ts - Date.now();
  if (ms <= 0) return "expired";
  var mins = Math.floor(ms / 60000);
  if (mins < 60) return mins + " min left";
  var hours = Math.floor(mins / 60);
  if (hours < 48) return hours + " h left";
  return Math.floor(hours / 24) + " days left";
}

/* ---------- clipboard ---------- */
function copyText(text, okMessage) {
  function fallback() {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    toast(ok ? okMessage : "Copy failed — select the text manually.");
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text)
      .then(function () { toast(okMessage); })
      .catch(fallback);
  } else { fallback(); }
}

/* ---------- views ---------- */
var createView = $("view-create");
var viewerView = $("view-viewer");

function showCreateView() {
  hide(viewerView); show(createView);
  document.title = "SecretDrop — Self-Destructing Secrets";
  renderMySecrets();
}
function showViewerView() {
  hide(createView); show(viewerView);
  document.title = "SecretDrop — Open a secret";
  window.scrollTo(0, 0);
}

/* ---------- create flow ---------- */
var lastCreatedLink = "";
var lastCreatedId = "";

function selectedExpiry() {
  var checked = document.querySelector('input[name="expiry"]:checked');
  return checked ? checked.value : "one-view";
}

function buildLink(id, keyB64OrNull) {
  var base = window.location.href.split("#")[0];
  var hash = "#s=" + encodeURIComponent(id);
  if (keyB64OrNull) hash += "&k=" + keyB64OrNull;
  return base + hash;
}

function onCreateSubmit(event) {
  event.preventDefault();
  setError($("createError"), "");
  var secret = $("secretInput").value;
  if (!secret.trim()) { setError($("createError"), "Write a secret first — the box is empty."); $("secretInput").focus(); return; }
  if (secret.length > MAX_CHARS) { setError($("createError"), "That secret is over 10,000 characters. Shorten it and try again."); return; }
  if (!cryptoAvailable()) {
    setError($("createError"), "WebCrypto is not available in this browser / context. SecretDrop needs a secure context (https or localhost / file) and a modern browser.");
    return;
  }
  var password = $("passwordInput").value;
  var expiry = selectedExpiry();
  var btn = $("createBtn");
  btn.disabled = true;
  btn.textContent = "Encrypting…";

  var id = newId();
  var expiresAt = expiryMsFor(expiry) ? Date.now() + expiryMsFor(expiry) : null;

  generateDataKey()
    .then(function (dataKey) {
      return encryptWithKey(dataKey, secret).then(function (enc) {
        return { dataKey: dataKey, enc: enc };
      });
    })
    .then(function (pair) {
      if (!password) {
        // No password: the raw key goes in the URL fragment only.
        return exportRawKey(pair.dataKey).then(function (raw) {
          return { enc: pair.enc, keyB64: bufToB64url(raw), salt: null, wrapped: null };
        });
      }
      // Password: wrap the data key with a PBKDF2-derived key; the link gets no key.
      var salt = randomBytes(16);
      return derivePasswordKey(password, salt).then(function (pwKey) {
        return exportRawKey(pair.dataKey).then(function (raw) {
          var wrapIv = randomBytes(12);
          return crypto.subtle.encrypt({ name: "AES-GCM", iv: wrapIv }, pwKey, raw)
            .then(function (wrappedCt) {
              return {
                enc: pair.enc, keyB64: null,
                salt: bufToB64url(salt),
                wrapped: { iv: bufToB64url(wrapIv), data: bufToB64url(wrappedCt) }
              };
            });
        });
      });
    })
    .then(function (out) {
      var rec = {
        v: 1, id: id,
        iv: out.enc.iv, data: out.enc.data,
        salt: out.salt, wrappedKey: out.wrapped,
        hasPassword: !!password,
        createdAt: Date.now(), expiresAt: expiresAt,
        maxViews: expiry === "one-view" ? 1 : null,
        views: 0, expiryLabel: expiryLabelFor(expiry)
      };
      // Save the ciphertext to the SERVER — this is what makes the link
      // work on any device. Only on success is the link shown.
      return saveRecord(rec).then(function (ok) {
        if (!ok) throw new Error("Could not reach the server — try again.");
        addToIndex(rec);
        return { rec: rec, keyB64: out.keyB64 };
      });
    })
    .then(function (done) {
      var rec = done.rec;
      var link = buildLink(id, done.keyB64);
      lastCreatedLink = link;
      lastCreatedId = id;
      $("secretLink").value = link;
      $("resultMeta").textContent =
        "Saved to server ✓ · " +
        (password ? "Password protected · " : "") +
        "Self-destructs: " + rec.expiryLabel +
        (expiresAt ? " · expires " + formatDate(expiresAt) : " · burns on first open") +
        " · works on any device.";
      var reminder = $("passwordReminder");
      if (password) {
        reminder.textContent = "Remember: share the password separately from the link — it is not in the link and cannot be recovered if you forget it.";
        show(reminder);
      } else { hide(reminder); }
      hide($("createForm"));
      show($("createResult"));
      renderMySecrets();
      $("secretLink").focus();
      $("secretLink").select();
      toast("Secret link created — saved to server ✓");
    })
    .catch(function (err) {
      setError($("createError"), "Could not create the secret: " + (err && err.message ? err.message : "encryption failed."));
    })
    .finally(function () {
      btn.disabled = false;
      btn.innerHTML = '<span aria-hidden="true">✦</span> Create secret link';
    });
}

/* ---------- viewer flow ---------- */
var pendingView = null; // { id, rec }

function viewerShowLoading() {
  show($("viewerLoading")); hide($("viewerSecret")); hide($("viewerPassword")); hide($("viewerError"));
}
function viewerShowError(title, text, icon) {
  hide($("viewerLoading")); hide($("viewerSecret")); hide($("viewerPassword"));
  $("viewerErrorTitle").textContent = title;
  $("viewerErrorText").textContent = text;
  $("viewerErrorIcon").textContent = icon || "🔥";
  show($("viewerError"));
}
function viewerShowPassword() {
  hide($("viewerLoading")); hide($("viewerSecret")); hide($("viewerError"));
  setError($("passwordError"), "");
  $("viewerPasswordInput").value = "";
  show($("viewerPassword"));
  $("viewerPasswordInput").focus();
}
function viewerShowSecret(plaintext, rec) {
  hide($("viewerLoading")); hide($("viewerPassword")); hide($("viewerError"));
  $("revealedSecret").textContent = plaintext;
  var parts = [];
  parts.push("Created " + formatDate(rec.createdAt));
  if (rec.expiresAt) parts.push("would have expired " + formatDate(rec.expiresAt));
  if (rec.maxViews) parts.push("burned after 1 view — this was that view");
  $("viewerMeta").textContent = parts.join(" · ") + ".";
  show($("viewerSecret"));
  renderMySecrets();
}

function burnIfNeeded(rec) {
  // Returns a Promise<boolean>: true if the record was deleted by this view.
  var nextViews = (rec.views || 0) + 1;
  if (rec.maxViews && nextViews >= rec.maxViews) {
    return deleteRecord(rec.id).then(function () { return true; });
  }
  rec.views = nextViews;
  updateIndexViews(rec.id, nextViews);
  return saveRecord(rec).then(function () { return false; })
    .catch(function () { return false; });
}

function decryptAndReveal(rec, dataKey) {
  return decryptWithKey(dataKey, rec.iv, rec.data)
    .then(function (plaintext) {
      return burnIfNeeded(rec).then(function () {
        viewerShowSecret(plaintext, rec);
      });
    })
    .catch(function () {
      viewerShowError(
        "Could not open this secret",
        "The key in this link does not match the stored secret, or the stored data was changed. The secret was not burned — check that you copied the full link.",
        "🔑"
      );
    });
}

function openSecretFromHash() {
  var hash = window.location.hash.slice(1);
  if (!hash) { showCreateView(); return; }
  var params = new URLSearchParams(hash);
  var id = params.get("s");
  var keyB64 = params.get("k");
  if (!id) { showCreateView(); return; }

  showViewerView();
  viewerShowLoading();

  loadRecord(id).then(function (rec) {
    if (!rec) {
      viewerShowError(
        "This secret has burned",
        "It was already opened once, it expired, it was deleted by its creator, or it was never created. There is nothing left to show, and no way to recover it.",
        "🔥"
      );
      return;
    }
    if (isExpired(rec)) {
      deleteRecord(rec.id);
      viewerShowError(
        "This secret expired",
        "Its timer (" + rec.expiryLabel + ") ran out, so it was deleted. Expired secrets cannot be recovered.",
        "⏱️"
      );
      return;
    }
    if (!cryptoAvailable()) {
      viewerShowError("Cannot decrypt in this browser", "WebCrypto is not available here. Try opening the link in a modern browser in a secure context.", "⚠️");
      return;
    }
    pendingView = { id: id, rec: rec };

    if (rec.hasPassword) {
      // Password mode: no key in the link is expected. Ask for the password.
      viewerShowPassword();
      return;
    }
    if (!keyB64) {
      viewerShowError(
        "This link is missing its key",
        "The decryption key lives in the link fragment (#k=…). This link does not have one — it may have been copied incompletely. Ask the sender to resend the full link.",
        "🔑"
      );
      return;
    }
    var keyBuf;
    try { keyBuf = b64urlToBuf(keyB64); } catch (e) {
      viewerShowError("This link is damaged", "The key in the link could not be read. Ask the sender to resend the full link.", "🔑");
      return;
    }
    importRawKey(keyBuf)
      .then(function (key) { return decryptAndReveal(rec, key); })
      .catch(function () {
        viewerShowError("This link is damaged", "The key in the link is not a valid encryption key. Ask the sender to resend the full link.", "🔑");
      });
  }).catch(function () {
    viewerShowError(
      "Could not reach the server",
      "The secret could not be loaded right now — check your connection and try again. The secret has not been burned.",
      "📡"
    );
  });
}

function onPasswordSubmit(event) {
  event.preventDefault();
  if (!pendingView) return;
  var password = $("viewerPasswordInput").value;
  if (!password) { setError($("passwordError"), "Enter the password the sender gave you."); return; }
  var rec = pendingView.rec;
  setError($("passwordError"), "");
  viewerShowLoading();
  var saltBuf;
  try { saltBuf = b64urlToBuf(rec.salt); } catch (e) {
    viewerShowError("This secret is damaged", "Its stored password data could not be read.", "⚠️");
    return;
  }
  derivePasswordKey(password, saltBuf)
    .then(function (pwKey) {
      return crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(b64urlToBuf(rec.wrappedKey.iv)) },
        pwKey, b64urlToBuf(rec.wrappedKey.data)
      );
    })
    .then(function (rawKeyBuf) { return importRawKey(rawKeyBuf); })
    .then(function (dataKey) { return decryptAndReveal(rec, dataKey); })
    .catch(function () {
      // Wrong password: do NOT burn the secret.
      viewerShowPassword();
      setError($("passwordError"), "Wrong password — try again. The secret has not been burned.");
    });
}

/* ---------- my secrets list ---------- */
function renderMySecrets() {
  var entries = loadIndex();
  entries.sort(function (a, b) { return b.createdAt - a.createdAt; });
  // Refresh each entry against the server so burned/expired secrets drop
  // out of the list and the view count is the server's count. If the server
  // cannot be reached, fall back to the local metadata as-is.
  Promise.all(entries.map(function (entry) {
    return loadRecord(entry.id).then(function (rec) {
      if (!rec) return null;
      if (isExpired(rec)) { deleteRecord(rec.id); return null; }
      entry.views = rec.views || 0;
      return entry;
    }).catch(function () { return entry; });
  })).then(function (live) {
    var list = live.filter(function (e) { return !!e; });
    saveIndex(list);
    paintMySecrets(list);
  });
}
function paintMySecrets(list) {
  $("mySecretsCount").textContent = String(list.length);
  var ul = $("mySecretsList");
  var empty = $("mySecretsEmpty");
  if (!list.length) { show(empty); hide(ul); ul.innerHTML = ""; return; }
  hide(empty); show(ul);
  ul.innerHTML = "";
  list.forEach(function (entry) {
    var li = document.createElement("li");
    var idSpan = document.createElement("span");
    idSpan.className = "secret-id";
    idSpan.textContent = "#" + entry.id;
    li.appendChild(idSpan);

    var meta = document.createElement("span");
    meta.className = "secret-meta";
    var when = "Created " + formatDate(entry.createdAt);
    var exp = entry.expiresAt ? " · expires " + formatDate(entry.expiresAt) + " (" + timeLeft(entry.expiresAt) + ")" : " · " + entry.expiryLabel;
    var views = entry.maxViews ? " · " + entry.views + " / 1 views" : " · " + entry.views + " views";
    var strong = document.createElement("strong");
    strong.textContent = entry.hasPassword ? "Password protected" : "No password";
    meta.appendChild(strong);
    meta.appendChild(document.createTextNode(" — " + when + exp + views));
    li.appendChild(meta);

    var pill = document.createElement("span");
    pill.className = "pill " + (entry.hasPassword ? "pill-locked" : "pill-live");
    pill.textContent = entry.hasPassword ? "🔐 Locked" : "● Live";
    li.appendChild(pill);

    var del = document.createElement("button");
    del.type = "button";
    del.className = "btn btn-danger-ghost btn-small";
    del.textContent = "Burn now";
    del.addEventListener("click", function () {
      deleteRecord(entry.id).then(function () {
        renderMySecrets();
        toast("Secret burned and deleted.");
      });
    });
    li.appendChild(del);
    ul.appendChild(li);
  });
}

/* ---------- password strength + generator ---------- */
function passwordStrength(pw) {
  if (!pw) return { score: 0, label: "" };
  var score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  var labels = ["Very weak", "Weak", "Fair", "Good", "Strong", "Very strong"];
  var colors = ["#ff5a6e", "#ff5a6e", "#f5a524", "#f5c86b", "#22d3a5", "#22d3a5"];
  return { score: score, label: labels[score], color: colors[score] };
}
function generatePassword() {
  var chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
  var bytes = randomBytes(16);
  var pw = "";
  for (var i = 0; i < 16; i++) pw += chars[bytes[i] % chars.length];
  var input = $("passwordInput");
  input.type = "text";
  input.value = pw;
  $("togglePassword").textContent = "Hide";
  input.dispatchEvent(new Event("input"));
  input.focus();
  input.select();
  toast("Strong password generated — copy it and share it separately from the link.");
}

/* ---------- wire up ---------- */
function init() {
  $("createForm").addEventListener("submit", onCreateSubmit);
  $("passwordForm").addEventListener("submit", onPasswordSubmit);

  $("secretInput").addEventListener("input", function () {
    $("charCount").textContent = $("secretInput").value.length.toLocaleString() + " / 10,000";
  });

  $("passwordInput").addEventListener("input", function () {
    var pw = $("passwordInput").value;
    var wrap = $("strengthWrap");
    if (!pw) { hide(wrap); return; }
    show(wrap);
    var s = passwordStrength(pw);
    $("strengthFill").style.width = (s.score / 5 * 100) + "%";
    $("strengthFill").style.background = s.color;
    $("strengthText").textContent = s.label + " — use 12+ characters with mixed case, numbers and symbols.";
  });

  $("togglePassword").addEventListener("click", function () {
    var input = $("passwordInput");
    var showing = input.type === "text";
    input.type = showing ? "password" : "text";
    $("togglePassword").textContent = showing ? "Show" : "Hide";
    input.focus();
  });
  $("generatePassword").addEventListener("click", generatePassword);

  $("copyLinkBtn").addEventListener("click", function () {
    copyText($("secretLink").value, "Link copied — share it once, it burns on first open.");
  });
  $("openLinkBtn").addEventListener("click", function () {
    if (lastCreatedLink) window.open(lastCreatedLink, "_blank", "noopener");
  });
  $("burnNowBtn").addEventListener("click", function () {
    if (!lastCreatedId) return;
    var id = lastCreatedId;
    deleteRecord(id).then(function () {
      lastCreatedId = ""; lastCreatedLink = "";
      show($("createForm"));
      hide($("createResult"));
      $("secretInput").value = "";
      $("passwordInput").value = "";
      hide($("strengthWrap"));
      $("charCount").textContent = "0 / 10,000";
      renderMySecrets();
      toast("Secret burned and deleted before anyone opened it.");
    });
  });
  $("createAnother").addEventListener("click", function () {
    show($("createForm"));
    hide($("createResult"));
    $("secretInput").value = "";
    $("passwordInput").value = "";
    hide($("strengthWrap"));
    $("charCount").textContent = "0 / 10,000";
    lastCreatedLink = ""; lastCreatedId = "";
    $("secretInput").focus();
  });

  $("copySecretBtn").addEventListener("click", function () {
    copyText($("revealedSecret").textContent, "Secret copied to clipboard.");
  });
  $("downloadSecretBtn").addEventListener("click", function () {
    var blob = new Blob([$("revealedSecret").textContent], { type: "text/plain;charset=utf-8" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "secretdrop-secret.txt";
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  });
  $("viewerHomeBtn").addEventListener("click", goHome);
  $("errorHomeBtn").addEventListener("click", goHome);
  $("brandLink").addEventListener("click", function (e) { e.preventDefault(); goHome(); });
  $("refreshMySecrets").addEventListener("click", function () { renderMySecrets(); toast("Refreshed."); });

  window.addEventListener("hashchange", function () {
    if (window.location.hash && window.location.hash.indexOf("#s=") === 0) openSecretFromHash();
    else showCreateView();
  });

  if (!cryptoAvailable()) {
    setError($("createError"), "WebCrypto is not available in this browser / context. SecretDrop needs a secure context and a modern browser — try Chrome, Edge or Firefox over https, localhost, or by opening the file directly.");
  }

  pruneExpired();
  // Route on load: a #s=... link opens the viewer, anything else is the creator.
  if (window.location.hash && window.location.hash.indexOf("#s=") === 0) openSecretFromHash();
  else showCreateView();
}

function goHome() {
  history.pushState(null, "", window.location.pathname + window.location.search);
  pendingView = null;
  showCreateView();
  window.scrollTo(0, 0);
}

document.addEventListener("DOMContentLoaded", init);

/* Test hook (no UI effect): lets automated tests drive the real store +
 * crypto code paths without a browser. */
if (typeof window !== "undefined") {
  window.SecretDrop = {
    saveRecord: saveRecord, loadRecord: loadRecord, deleteRecord: deleteRecord,
    isExpired: isExpired, addToIndex: addToIndex, loadIndex: loadIndex,
    generateDataKey: generateDataKey, exportRawKey: exportRawKey,
    importRawKey: importRawKey, encryptWithKey: encryptWithKey,
    decryptWithKey: decryptWithKey, derivePasswordKey: derivePasswordKey,
    newId: newId, bufToB64url: bufToB64url, b64urlToBuf: b64urlToBuf
  };
}
