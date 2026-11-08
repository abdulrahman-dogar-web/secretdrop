# SecretDrop — Self-Destructing Secrets

Share a password, token, or private note with a link that **burns after it is read** — encrypted in your browser before anything is stored.

No account. No sign-up. No tracking. Server-backed, so a link works on any device.

## How it works (server-backed)

1. **Write & encrypt.** You type a secret. Your browser generates a random AES-256-GCM key and encrypts the text on your device, before anything is stored.
2. **Save the ciphertext to the server.** The encrypted record is `PUT` to a key-value store (KVdb by default — see `config.js`; set `apiBase` there to use a self-hosted backend instead). The server only ever receives ciphertext — never the key, never the plaintext.
3. **Share the link.** You get a one-time link like `index.html#s=<id>&k=<key>`. The key travels only in the URL fragment (`#k=…`), which browsers never send to a server.
4. **It burns.** The recipient opens the link on any device, the browser fetches the ciphertext from the server and decrypts it with the key from the fragment, then **deletes the record from the server**. A second open shows “burned / expired”.

> “My secrets” is a **local list only**: the server cannot list keys, so the app keeps a metadata-only index in this browser's `localStorage` (id, creation time, expiry — never plaintext or keys) of the secrets you created here. A secret created on another device still opens from its link, but will not appear in this list.

## Run it

Open `index.html` in a modern browser (Chrome, Edge, or Firefox). That is the whole install — there is no build step. Serving it over HTTP is recommended (KVdb is reached over HTTPS from the page):

```text
python3 -m http.server 8000
# then open http://localhost:8000
```

Note: the KVdb account behind the configured bucket must be email-verified before server writes work; until then, creating a secret shows “Could not reach the server — try again.”

## Features

- **Create a secret** — up to 10,000 characters, with a live character counter.
- **Client-side AES-256-GCM encryption** via the WebCrypto API. A fresh random 256-bit key and a fresh random IV are generated for every secret. The plaintext never leaves the browser unencrypted.
- **Key in the URL fragment only** — the link looks like `index.html#s=<id>&k=<key>`. The key is in the `#` fragment, which browsers never send in HTTP requests. The key is never written to `localStorage`, never logged, and never sent anywhere.
- **Optional password protection** — when a password is set, the data key is wrapped with a PBKDF2-derived key (250,000 iterations, SHA-256, random 16-byte salt) and the key is **not** put in the link. The recipient must enter the password to open it. Includes a password-strength meter and a strong-password generator.
- **Self-destruct choices** — burn after 1 view, or expire after 1 hour, 24 hours, or 7 days.
- **Burn after reading** — opening a one-view secret deletes it from the server immediately after a successful decrypt. Opening it again shows a clear **“burned / expired”** state. Expired secrets are deleted and show an “expired” state.
- **Wrong password / wrong key does not burn** — a failed open does not count as a read, so the secret survives a typo.
- **One-time link with copy button**, plus an “open link (preview as recipient)” button so you can test the burn flow yourself.
- **Copy secret / download as `.txt`** on the viewer screen, after the secret has burned.
- **Burn now** — delete any secret early, from the result panel or from “My secrets”.
- **My secrets** — secrets created in this browser (a local metadata-only list — see above), listed with metadata only (never plaintext): creation time, expiry, view count, password status, and a burn button.
- **Premium dark UI** — responsive, mobile-friendly, keyboard-accessible, with toast notifications and a reduced-motion mode.

## How it works (detail)

1. **Write & encrypt.** You type a secret. Your browser generates a random AES-256-GCM key and encrypts the text on your device, before anything is stored.
2. **Share the link.** You get a one-time link. The key travels only in the URL fragment (`#k=…`), which is never sent to a server.
3. **It burns.** The recipient opens the link, the browser fetches the encrypted secret from the server, decrypts it with the key from the fragment, then deletes the encrypted copy from the server. A second open shows “burned / expired”.

### Burn rules, plainly

| Choice | Behaviour |
|---|---|
| After 1 view | The first successful open deletes the secret. A second open shows “burned”. |
| 1 hour / 24 hours / 7 days | The secret can be opened until the timer ends, then it is deleted and shows “expired”. |
| Wrong password / wrong key | Nothing is shown and nothing is deleted — the view does not count. |
| Burn now | The creator can delete a secret at any time from “My secrets”. |

### Sharing safely

- Send the link in one channel and the password (if any) in another.
- Tell the recipient to open it only when ready to copy it — one view means one chance.
- Do not post a one-time link in a public chat. Anyone with the link (and password, if set) who opens it first gets the secret.
- For truly sensitive material, remember the server stores only ciphertext — but anyone who opens the link first gets the plaintext.

## Try the burn flow (60 seconds)

1. Open `index.html`.
2. Type a test secret, e.g. `test-secret-123`, leave expiry on **After 1 view**, and click **Create secret link**.
3. Click **Copy link**, then **Open link (preview as recipient)** — or paste the link into a new tab, another browser, or another device: it works anywhere, because the secret lives on the server.
4. The secret is revealed and immediately burned. Copy it if you need it.
5. Open the same link again (or refresh the viewer tab) — you will see **“This secret has burned”**.
6. Check **My secrets** — the burned secret is gone from the list.

To test the password flow, repeat with a password set: the link will contain no `&k=…` part, and the viewer will ask for the password first. A wrong password shows an error and does **not** burn the secret.

To test expiry, create a secret with **1 hour** expiry — it stays openable until the hour ends. (Do not wait an hour to test: the expiry check runs on every open, and expired records are pruned whenever the page loads or the list refreshes.)

## Testing

- `node --check app.js` / `node --check store.js` / `node --check config.js` — syntax checks (must exit 0).
- Automated flow test against a local mock KVdb server (mock + test scripts are not shipped — see `TEST-LOG.md` for the exact checks and how they were run): it drives the real `store.js` and the real app logic (encrypt → save → read on a fresh “second device” → burn → second open shows burned; expiry deletes the record).

## Project structure

```text
secretdrop/
├── index.html   # Page structure: creator, How it works, Security, My secrets, viewer
├── styles.css   # Premium dark UI, responsive, no framework
├── config.js    # Server config: KVdb bucket + prefix, apiBase ("" = KVdb)
├── store.js     # window.KVStore: PUT/GET/DELETE against KVdb or apiBase
├── app.js       # All logic: WebCrypto, server store, burn/expiry, routing
├── TEST-LOG.md  # Local mock-server test results
├── README.md    # This file
├── LICENSE      # MIT License
└── .gitignore   # Node / OS / editor artefacts
```

## Security model — honest limitations

### What this does

- AES-256-GCM encryption via the browser WebCrypto API, with a fresh random key and IV per secret.
- Optional password protection: the key is wrapped with a PBKDF2-derived key (250,000 iterations, SHA-256, random salt).
- The key is only in the URL fragment (`#k=…`). Fragments are not sent in HTTP requests.
- Burn-after-reading and expiry are enforced on read; burned secrets are deleted from the server.

### Honest limitations

- **Server stores ciphertext:** the encrypted secret lives on the server until it burns or expires. The server never sees the key or the plaintext, but anyone with access to the server store could see (and delete) the ciphertext.
- **Anyone with access to this browser** can open DevTools and read the local metadata index — it holds no plaintext and no keys, so they still cannot read a secret without the key / password.
- **“My secrets” is local only:** it lists secrets created in this browser. A secret created on another device will not appear there (its link still works).
- **Do not use this app** for real credentials, banking details, or anything whose leak would cause real harm. Use a proper audited secret service for that.
- KVdb has a rate limit (1000 requests/hour on the bucket used here) and no server-side rate limiting is implemented in this static front end.

## Browser support

Requires a modern browser with WebCrypto (`crypto.subtle`) in a secure context: Chrome, Edge, or Firefox, over `https`, `localhost`, or by opening the file directly (`file://`). Very old browsers are not supported.

## Tech

HTML + CSS + vanilla JavaScript. No framework, no build step, no dependencies at runtime (Google Fonts is the only external request, for Inter / JetBrains Mono — the app works without it, falling back to system fonts). The data layer is KVdb (hosted key-value store, reached directly from the browser) with a `config.js` switch (`apiBase`) to a self-hosted backend.

## Screenshots

Screenshots are not included in this repo yet. To add them:

1. Open `index.html` in a browser at desktop width (1280px) and at mobile width (390px).
2. Capture the creator screen and the viewer screen (revealed secret, and the burned state).
3. Save them under `docs/screenshots/` as `creator-desktop.png`, `viewer-desktop.png`, and `creator-mobile.png`.
4. Reference them here, e.g. `![Creator screen](docs/screenshots/creator-desktop.png)`.

## License

MIT License — see [LICENSE](LICENSE). Copyright © 2026 Mr. Abdul Rahman Dogar.
