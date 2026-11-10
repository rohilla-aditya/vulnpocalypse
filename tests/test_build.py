import asyncio
import json

import httpx
import pytest

import test_sources as fixtures
from app import build as build_mod
from app.config import settings


def test_static_build_writes_site(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "cache_file", tmp_path / "cache.json")
    monkeypatch.setattr(settings, "public_url", "https://someone.github.io/repo")
    out = tmp_path / "dist"
    asyncio.run(build_mod.build(out, fixtures.client()))
    feed = json.loads((out / "feed.json").read_text())
    assert feed["tabs"][0]["items"][0]["ref"] == "CVE-2026-0001"
    assert feed["next_refresh_at"] > feed["generated_at"]
    page = (out / "index.html").read_text()
    assert 'content="https://someone.github.io/repo/og.png"' in page
    # Works from a sub-path: no root-absolute asset URLs.
    assert 'href="/' not in page and 'src="/' not in page
    assert (out / "app.js").exists() and (out / "og.png").exists()


def test_static_build_refuses_to_publish_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "cache_file", tmp_path / "cache.json")
    down = fixtures.client(lambda request: httpx.Response(500))
    with pytest.raises(SystemExit):
        asyncio.run(build_mod.build(tmp_path / "dist", down))
    assert not (tmp_path / "dist").exists()
