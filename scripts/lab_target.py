from __future__ import annotations

import asyncio
import hashlib
import os
import time
from collections import defaultdict, deque

from aiohttp import web


RATE_WINDOW_SECONDS = 10
RATE_LIMIT_LOGIN = 8
_login_hits: dict[str, deque[float]] = defaultdict(deque)


def _client_ip(request: web.Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    peer = request.transport.get_extra_info("peername") if request.transport else None
    return str(peer[0]) if peer else "unknown"


def _trim_hits(hits: deque[float], now: float) -> None:
    while hits and now - hits[0] > RATE_WINDOW_SECONDS:
        hits.popleft()


async def index(request: web.Request) -> web.Response:
    html = """
    <html>
      <head><title>AIDOS Legal Lab</title></head>
      <body>
        <h1>AIDOS Legal Lab</h1>
        <p>Authorized local-only test target for DoS assessment workflows.</p>
        <a href="/unlimited">Unlimited endpoint</a><br/>
        <a href="/slow">Slow endpoint</a><br/>
        <a href="/api/search?q=test">Search endpoint</a><br/>
        <form action="/login" method="post">
          <input name="username" />
          <input name="password" type="password" />
          <button type="submit">Login</button>
        </form>
      </body>
    </html>
    """
    return web.Response(text=html, content_type="text/html")


async def unlimited(request: web.Request) -> web.Response:
    return web.json_response({"ok": True, "endpoint": "unlimited", "ts": time.time()})


async def slow(request: web.Request) -> web.Response:
    await asyncio.sleep(1.25)
    return web.json_response({"ok": True, "endpoint": "slow"})


async def search(request: web.Request) -> web.Response:
    q = request.query.get("q", "a")
    rounds = min(max(len(q) * 5000, 10000), 300000)
    payload = q.encode("utf-8", errors="ignore")
    digest = b"seed"
    for _ in range(rounds):
        digest = hashlib.sha256(digest + payload).digest()
    return web.json_response(
        {"ok": True, "endpoint": "search", "q_len": len(q), "digest_prefix": digest.hex()[:12]}
    )


async def login(request: web.Request) -> web.Response:
    now = time.monotonic()
    ip = _client_ip(request)
    hits = _login_hits[ip]
    _trim_hits(hits, now)
    hits.append(now)

    if len(hits) > RATE_LIMIT_LOGIN:
        return web.json_response(
            {
                "ok": False,
                "error": "rate_limited",
                "window_seconds": RATE_WINDOW_SECONDS,
                "limit": RATE_LIMIT_LOGIN,
            },
            status=429,
            headers={"Retry-After": "10"},
        )

    if request.content_type.startswith("application/json"):
        data = await request.json()
        username = str(data.get("username", ""))
    else:
        data = await request.post()
        username = str(data.get("username", ""))

    await asyncio.sleep(0.15)
    return web.json_response({"ok": True, "user": username, "hint": "test account only"})


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/unlimited", unlimited)
    app.router.add_get("/slow", slow)
    app.router.add_get("/api/search", search)
    app.router.add_post("/login", login)
    app.router.add_post("/api/upload", login)
    return app


if __name__ == "__main__":
    host = os.environ.get("AIDOS_LAB_HOST", "127.0.0.1")
    port = int(os.environ.get("AIDOS_LAB_PORT", "8081"))
    web.run_app(build_app(), host=host, port=port, access_log=None)
