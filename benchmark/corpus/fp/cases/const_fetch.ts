// Phase 3: a browser API client whose URL is a build-time constant.
//
// CWE-918 SSRF requires an attacker inducing the *server* to make a request.
// This runs in the user's own tab, and the host comes from a compile-time
// constant, not from request input. `path` is a plain parameter.
const API_BASE = "http://localhost:8000";

export async function request(path: string, init?: RequestInit) {
  return fetch(`${API_BASE}${path}`, init);
}

export async function badgeUrl() {
  return fetch(`${API_BASE}/public/visit/badge`);
}
