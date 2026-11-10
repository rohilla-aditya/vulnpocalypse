"""Static build: scrape once and write a self-contained site to a directory.

    python -m app.build dist

This is what the GitHub Pages workflow runs every hour. The output is the same
frontend as the live server, with the feed baked in as `feed.json`.
"""

from __future__ import annotations

import asyncio
import html
import json
import shutil
import sys
import time
from pathlib import Path

import httpx

from .config import settings
from .feed import Feed

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


async def build(out: Path, client: httpx.AsyncClient | None = None) -> dict:
    feed = Feed()
    feed.load()  # last good copy, if the workflow restored one
    await feed.refresh(client)
    feed.next_refresh_at = int(time.time()) + settings.refresh_seconds
    payload = feed.payload()

    if not any(tab["items"] for tab in payload["tabs"]):
        # Every source failed and there is no cache: keep whatever is already
        # published rather than replacing it with an empty page.
        raise SystemExit("no data scraped; refusing to publish an empty dashboard")

    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(STATIC_DIR, out)
    index = out / "index.html"
    index.write_text(
        index.read_text(encoding="utf-8").replace("__BASE_URL__", html.escape(settings.public_url, quote=True)),
        encoding="utf-8",
    )
    (out / "feed.json").write_text(json.dumps(payload), encoding="utf-8")
    (out / ".nojekyll").write_text("")
    return payload


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    payload = asyncio.run(build(out))
    for s in payload["sources"]:
        print(f"[{'  OK  ' if s['ok'] else 'FAILED'}] {s['label']:<28} {s['count']:>4} rows {s['error']}")
        for name in s["failed"]:
            print(f"           - down: {name}")
    print("stats:", json.dumps(payload["stats"], sort_keys=True))
    print(f"wrote {out}/")


if __name__ == "__main__":
    main()
