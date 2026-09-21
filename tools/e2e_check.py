"""
e2e_check.py - end-to-end check of the real UI against the real API, in a real browser.

Starts the FastAPI backend (uvicorn) and the built React app (vite preview), uploads a real
sample pcap through the page, and checks that the results render. Also saves screenshots
to docs/screenshots/ (used by the documentation and slides).

    cd frontend-developer && npm run build      # once
    python tools/e2e_check.py

Needs: pip install playwright   (uses the Microsoft Edge that ships with Windows; no browser download)
"""

import os
import subprocess
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SHOTS = os.path.join(ROOT, "docs", "screenshots")
SAMPLE = os.path.join(ROOT, "data", "samples", "aes128gcm16-dh19-tunnel-pfs-on__web_run1.pcap")
WEAK = os.path.join(ROOT, "data", "samples", "aes128-dh2-transport-pfs-off__icmp_run1.pcap")
API, WEB = "http://127.0.0.1:8000", "http://127.0.0.1:4173"


def wait_for(url, seconds=60):
    end = time.time() + seconds
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=2)
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError(f"{url} did not come up")


def main():
    os.makedirs(SHOTS, exist_ok=True)
    npm = "npm.cmd" if os.name == "nt" else "npm"
    procs = [
        subprocess.Popen([sys.executable, "-m", "uvicorn", "main:app", "--port", "8000"],
                         cwd=os.path.join(ROOT, "backend-developer"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        subprocess.Popen([npm, "run", "preview", "--", "--host", "127.0.0.1", "--port", "4173", "--strictPort"],
                         cwd=os.path.join(ROOT, "frontend-developer"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
    ]
    try:
        wait_for(API + "/health")
        wait_for(WEB)
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="msedge", headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 1000})
            errors = []
            page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda e: errors.append(str(e)))

            page.goto(WEB)
            page.get_by_text("Analysis engine ready").wait_for(timeout=15000)
            page.screenshot(path=os.path.join(SHOTS, "01-empty.png"))

            # real upload through the file input
            page.set_input_files("input[type=file]", SAMPLE)
            page.get_by_role("button", name="Analyze capture").click()
            page.locator(".gauge__level", has_text="LOW").wait_for(timeout=60000)
            assert page.locator(".gauge__score").inner_text() == "100"
            body = page.inner_text("body")
            for needle in ["LOW", "AES-GCM-16-128", "Group 19", "Web browsing", "Threat matrix", "Traffic timeline",
                           "declared by the testbed"]:
                assert needle in body, f"missing on page: {needle!r}"
            assert page.locator(".recharts-bar-rectangle").count() > 5, "timeline chart did not render bars"
            page.screenshot(path=os.path.join(SHOTS, "02-strong-web.png"), full_page=True)

            # report download (real PDF from the backend)
            page.get_by_text("Download report").click()
            with page.expect_download(timeout=60000) as dl:
                page.get_by_role("button", name="Executive summary (PDF)").click()
            path = dl.value.path()
            with open(path, "rb") as f:
                assert f.read(5) == b"%PDF-", "downloaded report is not a PDF"
            print("executive PDF downloaded:", dl.value.suggested_filename)

            # weak configuration
            page.set_input_files("input[type=file]", WEAK)
            page.get_by_role("button", name="Analyze capture").click()
            page.locator(".gauge__level", has_text="HIGH").wait_for(timeout=60000)
            assert page.locator(".gauge__score").inner_text() == "30"
            body = page.inner_text("body")
            for needle in ["AES-CBC-128", "Group 2 (1024-bit", "transport", "ICMP (ping)"]:
                assert needle in body, f"weak sample: missing {needle!r}"
            assert page.get_by_text("Analyzing...").count() == 0, "screenshot taken while still analysing"
            page.screenshot(path=os.path.join(SHOTS, "03-weak-icmp.png"), full_page=True)

            assert not errors, f"unexpected browser console errors: {errors}"

            # bad file is rejected by the UI/API without crashing the page (the browser logs the
            # expected HTTP 400 in its console, so console errors are only checked before this step)
            bad = os.path.join(ROOT, "tests", "fixtures", "SYNTHETIC_not_a_pcap.pcap")
            page.set_input_files("input[type=file]", bad)
            page.get_by_role("button", name="Analyze capture").click()
            page.get_by_text("Analysis failed").wait_for(timeout=30000)
            assert "valid capture" in page.inner_text("body")
            browser.close()
        print("E2E OK")
    finally:
        for pr in procs:  # npm spawns children: kill the whole tree
            if os.name == "nt":
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(pr.pid)], capture_output=True)
            else:
                pr.terminate()


if __name__ == "__main__":
    main()
