// Works out which address the website should call for the API. Kept free of `import.meta` so it can be
// unit-tested with plain Node (tests/test_api_url.py).
//
// Order of preference:
//   1. VITE_API_URL, when it points somewhere other than this computer (a deployed backend);
//   2. VS Code port forwarding / Dev Tunnels / GitHub Codespaces: the page is served from
//      "<name>-5173.<region>.devtunnels.ms" (or "...app.github.dev") and the API from the same name with
//      port 8000, so the API address is derived from the page address;
//   3. VITE_API_URL, or http://127.0.0.1:8000 for plain local use.

const DEFAULT_LOCAL_API = "http://127.0.0.1:8000";
const TUNNEL_SUFFIXES = [".devtunnels.ms", ".app.github.dev"];
const API_PORT = 8000;

export function isLocalUrl(url) {
  try {
    const host = new URL(url).hostname;
    return host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";
  } catch {
    return false;
  }
}

export function isTunnelHost(hostname) {
  return TUNNEL_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
}

/** "abc123-5173.inc1.devtunnels.ms" -> "abc123-8000.inc1.devtunnels.ms" (null if it does not look like a forwarded port) */
export function tunnelApiHost(hostname) {
  if (!isTunnelHost(hostname)) return null;
  const m = hostname.match(/^(.+)-(\d{2,5})\.(.+)$/);
  return m ? `${m[1]}-${API_PORT}.${m[3]}` : null;
}

export function resolveApiUrl(envUrl, loc) {
  const configured = (envUrl || "").trim().replace(/\/+$/, "");
  if (configured && !isLocalUrl(configured)) return configured;
  const apiHost = loc ? tunnelApiHost(loc.hostname) : null;
  if (apiHost) return `${loc.protocol}//${apiHost}`;
  return configured || DEFAULT_LOCAL_API;
}
