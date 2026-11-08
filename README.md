# SecretDrop — Self-Destructing Secrets

Share a password, token, or private note with a link that **burns after it is read** — encrypted in your browser before anything is stored.

No account. No sign-up. No backend. No tracking.

## Demo

Open `index.html` in a modern browser (Chrome, Edge, or Firefox). That is the whole install — there is no build step and no server to run.

```text
# Option 1 — double-click index.html
# Option 2 — serve it locally (any static server works):
python3 -m http.server 8000
# then open http://localhost:8000
```

> **Demo limitation, stated up front:** this build stores the encrypted secret in `localStorage` in **this browser only**. A link therefore only opens on the same browser / device that created it. There is no server in this repo, so there is no server-side delivery or server-side deletion. A production version would need a server store. See [Security model](#security-model--honest-limitations) below.

## Features

- **Create a secret** — up to 10,000 characters, with a live character counter.
- **Client-side AES-256-GCM encryption** via the WebCrypto API. A fresh random 256-bit key and a fresh random IV are generated for every secret. The plaintext never leaves the browser unencrypted.
- **Key in the URL fragment only** — the link looks like `index.html#s=<id>&k=<key>`. The key is in the `#` fragment, which browsers never send in HTTP requests. The key is never written to `localStorage`, never logged, and never sent anywhere.
- **Optional password protection** — when a password is set, the data key is wrapped with a PBKDF2-derived key (250,000 iterations, SHA-256, random 16-byte salt) and the key is **not** put in the link. The recipient must enter the password to open it. Includes a password-strength meter and a strong-password generator.
- **Self-destruct choices** — burn after 1 view, or expire after 1 hour, 24 hours, or 7 days.
- **Burn after reading** — opening a one-view secret deletes it from storage immediately after a successful decrypt. Opening it again shows a clear **“burned / expired”** state. Expired secrets are deleted and show an “expired” state.
- **Wrong password / wrong key does not burn** — a failed open does not count as a read, so the secret survives a typo.
- **One-time link with copy button**, plus an “open link (preview as recipient)” button so you can test the burn flow yourself.
- **Copy secret / download as `.txt`** on the viewer screen, after the secret has burned.
- **Burn now** — delete any secret early, from the result panel or from “My secrets”.
- **My secrets** — secrets created in this browser, listed with metadata only (never plaintext): creation time, expiry, view count, password status, and a burn button.
- **Premium dark UI** — responsive, mobile-friendly, keyboard-accessible, with toast notifications and a reduced-motion mode.

## How it works

1. **Write & encrypt.** You type a secret. Your browser generates a random AES-256-GCM key and encrypts the text on your device, before anything is stored.
2. **Share the link.** You get a one-time link. The key travels only in the URL fragment (`#k=…`), which is never sent to a server.
3. **It burns.** The recipient opens the link, the browser decrypts the secret with the key from the fragment, then deletes the encrypted copy. A second open shows “burned / expired”.

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
- For truly sensitive material, use a proper server-backed secret service — not this local demo.

## Try the burn flow (60 seconds)

1. Open `index.html`.
2. Type a test secret, e.g. `test-secret-123`, leave expiry on **After 1 view**, and click **Create secret link**.
3. Click **Copy link**, then **Open link (preview as recipient)** — or paste the link into a new tab in the same browser.
4. The secret is revealed and immediately burned. Copy it if you need it.
5. Open the same link again (or refresh the viewer tab) — you will see **“This secret has burned”**.
6. Check **My secrets** — the burned secret is gone from the list.

To test the password flow, repeat with a password set: the link will contain no `&k=…` part, and the viewer will ask for the password first. A wrong password shows an error and does **not** burn the secret.

To test expiry, create a secret with **1 hour** expiry — it stays openable until the hour ends. (Do not wait an hour in a demo: the expiry check runs on every open, and expired records are pruned whenever the page loads or the list refreshes.)

## Project structure

```text
secretdrop/
├── index.html   # Page structure: creator, How it works, Security, My secrets, viewer
├── styles.css   # Premium dark UI, responsive, no framework
├── app.js       # All logic: WebCrypto, localStorage store, burn/expiry, routing
├── README.md    # This file
├── LICENSE      # MIT License
└── .gitignore   # Node / OS / editor artefacts
```

## Security model — honest limitations

### What this does

- AES-256-GCM encryption via the browser WebCrypto API, with a fresh random key and IV per secret.
- Optional password protection: the key is wrapped with a PBKDF2-derived key (250,000 iterations, SHA-256, random salt).
- The key is only in the URL fragment (`#k=…`). Fragments are not sent in HTTP requests.
- Burn-after-reading and expiry are enforced on read; burned secrets are removed from storage.

### What this demo does NOT do

- **Local-only storage:** secrets live in `localStorage` in this browser. A link only works on the same browser / device that created it. There is no server, so there is no server-side deletion and no delivery to another device.
- **Anyone with access to this browser** can open DevTools and read the encrypted data in `localStorage` — they still cannot read the plaintext without the key / password.
- **Clearing browser data, private mode, or a different browser** will make links unreadable. That is expected for a local demo.
- **Do not use this demo** for real credentials, banking details, or anything whose leak would cause real harm. Use a proper server-backed secret service for that.
- This project makes **no claim** of a real backend or server-side deletion. Any deployment that adds a server must implement deletion on the server, short-lived records, and rate limiting — none of which exist here.

## Browser support

Requires a modern browser with WebCrypto (`crypto.subtle`) in a secure context: Chrome, Edge, or Firefox, over `https`, `localhost`, or by opening the file directly (`file://`). Very old browsers are not supported.

## Tech

HTML + CSS + vanilla JavaScript. No framework, no build step, no backend, no dependencies at runtime (Google Fonts is the only external request, for Inter / JetBrains Mono — the app works without it, falling back to system fonts).

## Screenshots

Screenshots are not included in this repo yet. To add them:

1. Open `index.html` in a browser at desktop width (1280px) and at mobile width (390px).
2. Capture the creator screen and the viewer screen (revealed secret, and the burned state).
3. Save them under `docs/screenshots/` as `creator-desktop.png`, `viewer-desktop.png`, and `creator-mobile.png`.
4. Reference them here, e.g. `![Creator screen](docs/screenshots/creator-desktop.png)`.

## License

MIT License — see [LICENSE](LICENSE). Copyright © 2026 Mr. Abdul Rahman Dogar.
