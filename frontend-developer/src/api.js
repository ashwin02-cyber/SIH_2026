// All communication with the FastAPI backend lives here.
// The base URL comes from VITE_API_URL (see .env / .env.example). On Vercel/Netlify set it
// in the project's environment-variable settings; it is baked in at build time.
// When the site is opened through VS Code port forwarding, the API address is derived from the page
// address instead (see apiUrl.js), so no rebuild is needed for a new forwarded hostname.

import { isTunnelHost, resolveApiUrl } from "./apiUrl";

export const API_URL = resolveApiUrl(import.meta.env.VITE_API_URL, typeof window === "undefined" ? null : window.location);

// Dev Tunnels (VS Code port forwarding) show a "you are about to visit a tunnel" warning page to browsers.
// This header lets our API calls through it; it is only sent when the site itself is opened through a tunnel.
const TUNNEL_HEADERS =
  typeof window !== "undefined" && isTunnelHost(window.location.hostname)
    ? { "X-Tunnel-Skip-AntiPhishing-Page": "true" }
    : {};

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request(path, options) {
  let response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      ...options,
      headers: { ...TUNNEL_HEADERS, ...(options && options.headers) },
    });
  } catch {
    throw new ApiError(
      `Cannot reach the analysis server at ${API_URL}. Is the backend running?`,
      0,
    );
  }
  if (!response.ok) {
    let detail = `Server returned ${response.status}`;
    try {
      const body = await response.json();
      if (body.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* body was not JSON - keep the generic message */
    }
    throw new ApiError(detail, response.status);
  }
  return response;
}

export async function checkHealth() {
  const response = await request("/health");
  return response.json();
}

export async function listSamples() {
  const response = await request("/samples");
  return (await response.json()).samples;
}

export async function analyzeFile(file) {
  const form = new FormData();
  form.append("file", file);
  const response = await request("/analyze", { method: "POST", body: form });
  return response.json();
}

export async function analyzeSample(name) {
  const response = await request(`/analyze/sample/${encodeURIComponent(name)}`, { method: "POST" });
  return response.json();
}

// kind: "executive" | "technical"   format: "pdf" | "html"
export async function downloadReport(analysis, kind, format) {
  const response = await request(`/report/${kind}.${format}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(analysis),
  });
  const blob = await response.blob();
  const base = analysis.filename.replace(/\.[^.]+$/, "") || "analysis";
  saveBlob(blob, `${base}-${kind}.${format}`);
}

export function downloadJson(analysis) {
  const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: "application/json" });
  saveBlob(blob, `${analysis.filename.replace(/\.[^.]+$/, "") || "analysis"}.json`);
}

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
