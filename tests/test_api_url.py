"""Which API address the website uses (frontend-developer/src/apiUrl.js), tested with plain Node,
and the backend CORS settings used for VS Code port forwarding (Dev Tunnels)."""
import json
import os
import re
import subprocess

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

import main
from conftest import ROOT

APIURL = os.path.join(ROOT, "frontend-developer", "src", "apiUrl.js").replace("\\", "/")


def node(expr):
    code = f'import * as m from "file:///{APIURL}"; console.log(JSON.stringify({expr}));'
    out = subprocess.run(["node", "--input-type=module", "-e", code], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


LOCAL = "http://127.0.0.1:8000"


@pytest.mark.parametrize("env,loc,expected", [
    # plain local use
    (LOCAL, ("http:", "127.0.0.1"), LOCAL),
    (LOCAL, ("http:", "localhost"), LOCAL),
    ("", ("http:", "localhost"), LOCAL),
    # VS Code port forwarding: derive the forwarded 8000 address from the forwarded 5173 address
    (LOCAL, ("https:", "abc123xy-5173.inc1.devtunnels.ms"), "https://abc123xy-8000.inc1.devtunnels.ms"),
    ("", ("https:", "my-machine-name-5173.euw.devtunnels.ms"), "https://my-machine-name-8000.euw.devtunnels.ms"),
    (LOCAL, ("https:", "octo-space-abc-5173.app.github.dev"), "https://octo-space-abc-8000.app.github.dev"),
    # an explicit deployed backend always wins (Vercel/Netlify), even on a tunnel host
    ("https://api.example.com/", ("https:", "site.vercel.app"), "https://api.example.com"),
    ("https://api.example.com", ("https:", "abc-5173.inc1.devtunnels.ms"), "https://api.example.com"),
    # a tunnel-looking host without a port suffix is not guessed at
    (LOCAL, ("https:", "plain.devtunnels.ms"), LOCAL),
    # a non-tunnel host is never rewritten
    (LOCAL, ("https:", "example-5173.example.com"), LOCAL),
])
def test_resolve_api_url(env, loc, expected):
    got = node(f'm.resolveApiUrl({json.dumps(env)}, {{protocol: {json.dumps(loc[0])}, hostname: {json.dumps(loc[1])}}})')
    assert got == expected


def test_tunnel_host_detection():
    assert node('m.isTunnelHost("x-5173.inc1.devtunnels.ms")') is True
    assert node('m.isTunnelHost("localhost")') is False
    assert node('m.isLocalUrl("http://localhost:8000")') is True
    assert node('m.isLocalUrl("https://api.example.com")') is False


# ---------------------------------------------------------------- backend CORS
def _client(env):
    app = FastAPI()
    app.add_middleware(CORSMiddleware, **main.cors_settings(env))

    @app.get("/ping")
    def ping():
        return {"ok": True}
    return TestClient(app)


def _preflight(client, origin):
    return client.options("/ping", headers={"Origin": origin, "Access-Control-Request-Method": "POST",
                                            "Access-Control-Request-Headers": "content-type,x-tunnel-skip-antiphishing-page"})


TUNNEL_ENV = {"ALLOWED_ORIGINS": "http://127.0.0.1:5173,http://localhost:5173",
              "ALLOWED_ORIGIN_REGEX": r"https://.*\.devtunnels\.ms|https://.*\.app\.github\.dev"}


def test_cors_allows_forwarded_origin_including_the_tunnel_header():
    c = _client(TUNNEL_ENV)
    origin = "https://abc123xy-5173.inc1.devtunnels.ms"
    r = _preflight(c, origin)
    assert r.status_code == 200 and r.headers["access-control-allow-origin"] == origin
    assert "x-tunnel-skip-antiphishing-page" in r.headers["access-control-allow-headers"].lower()
    assert c.get("/ping", headers={"Origin": origin}).headers["access-control-allow-origin"] == origin


def test_cors_still_allows_local_origins_and_blocks_others_when_restricted():
    c = _client(TUNNEL_ENV)
    assert _preflight(c, "http://localhost:5173").headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-origin" not in _preflight(c, "https://evil.example.com").headers
    assert "access-control-allow-origin" not in _preflight(c, "http://abc-5173.devtunnels.ms.evil.com").headers


def test_cors_default_is_unchanged():
    assert main.cors_settings({}) == {"allow_origins": ["*"], "allow_origin_regex": None,
                                      "allow_methods": ["*"], "allow_headers": ["*"]}


def test_vite_config_allows_forwarded_hosts():
    text = open(os.path.join(ROOT, "frontend-developer", "vite.config.js"), encoding="utf-8").read()
    assert ".devtunnels.ms" in text and re.search(r"server:\s*\{\s*allowedHosts", text) and re.search(r"preview:\s*\{\s*allowedHosts", text)
