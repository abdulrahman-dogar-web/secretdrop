# SecretDrop — Test Log

Date: 2026-11-08. Scope: server-backed rebuild (KVdb via `store.js` / `config.js`).

## How it was tested

- **Syntax:** `node --check` on `config.js`, `store.js`, `app.js` — all exit 0.
- **Flow tests:** the real `store.js`, `config.js` and `app.js` were loaded in
  Node (minimal DOM/`localStorage` stubs) and driven against a local mock
  KVdb server (`/tmp/kvdb-mock/server.js`, in-memory, same
  `PUT/GET/DELETE /{bucket}/{key}` paths). `https://kvdb.io/…` fetches were
  rewritten to the mock so the real KVdb URL shape and `text/plain` PUT were
  exercised. No live KVdb request was made — the live KVdb account still
  needs email verification (parent's step), so live behaviour is
  **not yet verified**; the code paths are identical, only the transport
  origin differs.
- **"Second device":** a fresh Node process with empty `localStorage`
  (`/tmp/kvdb-mock/device-b-secretdrop.js`) that loads the real app files,
  GETs the record, decrypts it, and burns it.
- Test scripts (not shipped): `/tmp/kvdb-mock/test-secretdrop.js`,
  `/tmp/kvdb-mock/device-b-secretdrop.js`, `/tmp/kvdb-mock/server.js`,
  `/tmp/kvdb-mock/harness.js`.

## Results — 16/16 passed

| # | Check | Result |
|---|---|---|
| S2 | `config.js` has bucket `D6nggBKozgz4G6KNT1ha5A`, prefix `sd:`, `apiBase: ""` | PASS |
| S1 | KVStore put/get/del round-trip; GET missing → `null` | PASS |
| S1 | KVdb URL shape `https://kvdb.io/{bucket}/{prefix}{key}` + `text/plain` PUT (verified from the mock's request log) | PASS |
| S1 | put/del resolve `false`, never throw, on HTTP 403 | PASS |
| S3 | Create: real AES-256-GCM encrypt + KVStore PUT succeeds | PASS |
| S4 | Server only ever receives ciphertext — stored record contains no plaintext and no key | PASS |
| S4 | Local "My secrets" index holds metadata only (no ciphertext/key) | PASS |
| S5 | Second device (fresh process) GETs + decrypts the secret (`test-secret-123`) | PASS |
| S5 | Second open shows burned — record gone after the burn | PASS |
| S5 | Repeat open on a third device also finds nothing (burned) | PASS |
| S6 | Expired record detected by timestamp (`isExpired`) | PASS |
| S6 | Expired record deleted from server; later load → `null` | PASS |
| S7 | Password-wrapped secret opens on second device with the password | PASS |
| S7 | Wrong password cannot decrypt the secret | PASS |
| S7 | Wrong password does NOT burn the secret (record still on server) | PASS |
| S9 | `apiBase` path: PUT/GET/DELETE `/v1/kv/sd:<key>` with JSON body | PASS |

## Not covered by these tests (needs a browser / live KVdb)

- The rendered viewer/create UI (DOM wiring, toasts, QR of the link) — logic
  is the same code tested above, but no headless-browser run was done.
- Live KVdb: same code paths, but unverified until the KVdb account's email
  is verified and a real PUT succeeds from the Pages site.

## License

MIT License — © 2026 Mr. Abdul Rahman Dogar.
