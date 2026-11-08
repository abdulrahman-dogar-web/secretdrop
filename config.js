/* SecretDrop — server configuration.
 *
 * The app talks to the live backend at apiBase (Vercel + Vercel Blob,
 * durable storage) — PUT/GET/DELETE {apiBase}/v1/kv/{prefix}{key}.
 * Set apiBase to "" to fall back to KVdb directly (bucket below).
 *
 * © 2026 Mr. Abdul Rahman Dogar
 */
window.APP_CONFIG = {
  bucket: "D6nggBKozgz4G6KNT1ha5A",
  prefix: "sd:",
  apiBase: "https://apps-backend.abdulrahman-dogar.workers.dev"
};
