"""VULN-POCALYPSE NOW — a public, read-only dashboard of what is on fire.

No accounts, no keys, no user input reaching an upstream: the scraper runs on
a timer and visitors only ever read the cached result.
"""

from __future__ import annotations

import asyncio
import html
import logging
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .feed import feed

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("vuln-pocalypse")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
INDEX_HTML = (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@asynccontextmanager
async def lifespan(app: FastAPI):
    feed.load()
    task = asyncio.create_task(feed.run_forever()) if settings.auto_refresh else None
    log.info("ready | refresh every %ss | auto=%s", settings.refresh_seconds, settings.auto_refresh)
    yield
    if task:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="VULN-POCALYPSE NOW", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    )
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


@app.get("/api/health")
async def health():
    return {"ok": True, "generated_at": feed.generated_at}


# feed.json is what the page fetches; the same file exists in the static build.
@app.get("/feed.json")
@app.get("/api/feed")
async def api_feed():
    return JSONResponse(feed.payload(), headers={"Cache-Control": "public, max-age=60"})


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # Social-card tags need absolute URLs. Prefer the configured public URL;
    # the request's own base is the fallback for local runs.
    base = settings.public_url or str(request.base_url).rstrip("/")
    return HTMLResponse(INDEX_HTML.replace("__BASE_URL__", html.escape(base, quote=True)))


app.mount("/", StaticFiles(directory=STATIC_DIR), name="static")
