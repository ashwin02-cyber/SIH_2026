"""
tunnel_check.py - checks, in a real browser, that the site works when opened through VS Code port forwarding
(Dev Tunnels), WITHOUT needing a real tunnel.

It pretends the site is at  https://simsite-5173.sim.devtunnels.ms  and the API at
https://simsite-8000.sim.devtunnels.ms  (the same naming pattern VS Code uses) and routes those names to the
local servers, so the real front-end code, the real CORS rules and the real backend are exercised:

    - the page must work out the forwarded 8000 address by itself (src/apiUrl.js),
    - the browser's CORS check (incl. the pre-flight for the tunnel header) must pass,
    - "Try a sample" -> results -> PDF download must work.

Known limit of this check: Playwright's request interception cannot forward the BYTES of a browser file
upload, so the file-upload step itself is not exercised here (the sample button makes the same kind of
cross-origin API call without a file body). Uploading a file is covered by tools/e2e_check.py, which uses the
identical code path except for the base URL.

Start the servers first (see RUN_LOCAL.md, "Share it with VS Code port forwarding"):
    backend  on 127.0.0.1:8000 with ALLOWED_ORIGIN_REGEX set (so the test is meaningful)
    site     on 127.0.0.1:5173 (npm run preview)

    python tools/tunnel_check.py
Needs: pip install -r requirements-dev.txt   (uses the Microsoft Edge that ships with Windows)
"""

import http.client
import os
import sys

from playwright.sync_api import sync_playwright

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SITE, API = "simsite-5173.sim.devtunnels.ms", "simsite-8000.sim.devtunnels.ms"


def raw(port, method, path, headers):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    conn.request(method, path, headers=headers)
    r = conn.getresponse()
    r.read()
    return r.status, {k.lower(): v for k, v in r.getheaders()}


def server_checks():
    # 1. the backend must be restricted (otherwise the browser test would pass for the wrong reason)
    _, h = raw(8000, "OPTIONS", "/analyze", {"Origin": "https://evil.example.com", "Access-Control-Request-Method": "POST"})
    if "access-control-allow-origin" in h:
        sys.exit("The backend allows every origin (ALLOWED_ORIGINS is '*'). Start it with ALLOWED_ORIGINS and "
                 "ALLOWED_ORIGIN_REGEX as shown in RUN_LOCAL.md so this check is meaningful.")
    print("backend refuses an unknown origin: OK")
    origin = f"https://{SITE}"
    _, h = raw(8000, "OPTIONS", "/analyze", {"Origin": origin, "Access-Control-Request-Method": "POST",
                                             "Access-Control-Request-Headers": "x-tunnel-skip-antiphishing-page"})
    assert h.get("access-control-allow-origin") == origin, h
    print("backend allows the forwarded origin and the tunnel header: OK")

    # 2. Vite must answer to forwarded host names but not to arbitrary ones
    st, _ = raw(5173, "GET", "/", {"Host": SITE})
    assert st == 200, f"site answered {st} for a devtunnels host name"
    st, _ = raw(5173, "GET", "/", {"Host": "evil.example.com"})
    assert st == 403, f"site answered {st} for an unknown host name (expected 403)"
    print("site accepts *.devtunnels.ms and rejects unknown host names: OK")


def to_local(host, port):
    def handler(route, request):
        url = request.url.replace(f"https://{host}", f"http://127.0.0.1:{port}")
        route.fulfill(response=route.fetch(url=url))
    return handler


def main():
    server_checks()
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        ctx = browser.new_context(viewport={"width": 1280, "height": 1000}, accept_downloads=True)
        page = ctx.new_page()
        page.route(f"https://{SITE}/**", to_local(SITE, 5173))
        page.route(f"https://{API}/**", to_local(API, 8000))

        api_requests, errors = [], []
        page.on("request", lambda r: api_requests.append(r) if API in r.url else None)
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(str(e)))

        page.goto(f"https://{SITE}/")
        page.get_by_text("Analysis engine ready").wait_for(timeout=20000)
        assert api_requests, "the page never called the forwarded API address"
        assert all(r.url.startswith(f"https://{API}/") for r in api_requests), [r.url for r in api_requests]
        assert all(r.headers.get("x-tunnel-skip-antiphishing-page") == "true" for r in api_requests), "tunnel header missing"
        print(f"page derived the API address itself: https://{API}  ({len(api_requests)} calls, tunnel header sent): OK")

        page.get_by_role("button", name="aes128gcm16-dh19-tunnel-pfs-on__web", exact=True).click()
        page.locator(".gauge__level", has_text="LOW").wait_for(timeout=60000)
        assert page.locator(".gauge__score").inner_text() == "100"
        assert "Web browsing" in page.inner_text("body")
        assert any(r.method == "POST" and "/analyze/sample/" in r.url and r.url.startswith(f"https://{API}/") for r in api_requests)
        print("sample analysed through the forwarded API -> results: OK")

        page.get_by_text("Download report").click()
        with page.expect_download(timeout=60000) as dl:
            page.get_by_role("button", name="Executive summary (PDF)").click()
        with open(dl.value.path(), "rb") as f:
            assert f.read(5) == b"%PDF-"
        print("PDF report download through the forwarded API: OK")

        assert not errors, f"browser console errors: {errors}"
        browser.close()
    print("TUNNEL CHECK OK")


if __name__ == "__main__":
    main()
