"""The aggregate feed: scrape every source on a timer, serve the last good copy.

A source that fails keeps its previous items and is flagged in `sources`, so
one flaky upstream never blanks the dashboard.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import httpx

from .config import settings
from . import incidents
from .sources import CVE_RE, SOURCES, _why, active_sources, fetch_epss, fetch_fix_status, make_client, set_fix

log = logging.getLogger("vuln-pocalypse")

# Which sources feed which tab, in display order.
TABS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("exploited", "EXPLOITED IN THE WILD", ("kev",)),
    ("cves", "CRITICAL + HIGH CVEs", ("nvd", "ghsa")),
    ("advisories", "ADVISORIES", ("advisories",)),
    ("exploits", "PUBLIC EXPLOITS", ("exploits",)),
    ("pwned", "PWNED LEDGER", ("hibp", "sec")),
    ("ransom", "RANSOM CLAIMS", ("ransom",)),
    ("wire", "BREACH WIRE", ("wire",)),
    ("chatter", "CHATTER", ("hn", "forums", "fedi")),
)

# Sources whose rows carry a CVE id worth annotating with its EPSS score.
EPSS_SOURCES = ("kev", "nvd", "ghsa")
# Where incident headlines come from.
INCIDENT_SOURCES = ("wire", "hn", "forums", "fedi")
# CVE-record lookups per scrape for exploited CVEs whose patch status CISA's
# text does not settle. Results are cached, so this only bounds the first runs.
FIX_LOOKUPS_PER_RUN = 150
SOURCE_TIMEOUT = 180  # seconds; one stuck upstream must not stall the whole scrape


class Feed:
    def __init__(self) -> None:
        self._state: dict[str, dict[str, Any]] = {
            s.key: {"items": [], "stats": {}, "failed": [], "ok": None, "fetched_at": 0, "error": ""} for s in SOURCES
        }
        self.sources = active_sources()
        self.generated_at = 0
        self.next_refresh_at = 0
        self._payload: dict | None = None
        self._lock = asyncio.Lock()

    # -- scraping ----------------------------------------------------------

    async def refresh(self, client: httpx.AsyncClient | None = None) -> None:
        async with self._lock:
            own = client is None
            client = client or make_client()
            try:
                results = await asyncio.gather(
                    *(asyncio.wait_for(s.fetch(client), SOURCE_TIMEOUT) for s in self.sources), return_exceptions=True
                )
                now = int(time.time())
                for src, result in zip(self.sources, results):
                    st = self._state[src.key]
                    if isinstance(result, BaseException):
                        # Log the detail, publish only a status code or exception class.
                        log.warning("source %s failed: %r", src.key, result)
                        st["ok"] = False
                        st["error"] = _why(result)
                        continue
                    st.update(
                        items=result["items"],
                        stats=result.get("stats", {}),
                        failed=result.get("failed", []),
                        ok=True,
                        fetched_at=now,
                        error="",
                    )
                    if st["failed"]:
                        log.warning("source %s partial: %s", src.key, ", ".join(st["failed"]))
                await self._annotate_epss(client)
                await self._annotate_fix(client)
            finally:
                if own:
                    await client.aclose()
            self.generated_at = now
            self._payload = None
            self._save()
            log.info("refreshed | %s", " ".join(f"{k}={len(v['items'])}{'' if v['ok'] else '!'}" for k, v in self._state.items()))

    async def _annotate_epss(self, client: httpx.AsyncClient) -> None:
        """Tag CVE rows with their exploit-prediction score. Best effort."""
        rows = [i for k in EPSS_SOURCES for i in self._state[k]["items"] if CVE_RE.fullmatch(i.get("ref", ""))]
        try:
            scores = await asyncio.wait_for(fetch_epss(client, sorted({i["ref"] for i in rows})), 60)
        except Exception as exc:
            log.warning("epss annotation skipped: %r", exc)
            return
        for item in rows:
            item["tags"] = [t for t in item["tags"] if not t.startswith("EPSS ")]
            score = scores.get(item["ref"])
            if score is not None and score >= 0.01:
                item["tags"].append(f"EPSS {score:.0%}")
                item["epss"] = round(score, 4)
        self._state["kev"]["stats"]["epss_scored"] = len(scores)

    async def _annotate_fix(self, client: httpx.AsyncClient) -> None:
        """Settle PATCH UNKNOWN on exploited CVEs from their CVE records. Best effort."""
        kev = self._state["kev"]
        cache: dict[str, str] = kev.setdefault("fixcache", {})
        unknown = [i for i in kev["items"] if i.get("fix") == "unknown" and CVE_RE.fullmatch(i.get("ref", ""))]
        todo = [i["ref"] for i in unknown if i["ref"] not in cache][:FIX_LOOKUPS_PER_RUN]
        if todo:
            try:
                cache.update(await asyncio.wait_for(fetch_fix_status(client, todo), 90))
            except Exception as exc:
                log.warning("patch-status lookup skipped: %r", exc)
        for item in unknown:
            # A record that says nothing either way stays unknown; "open" needs explicit wording.
            if cache.get(item["ref"]) in ("patched", "open"):
                set_fix(item, cache[item["ref"]])
        # Keep the cache to CVEs still on the page.
        live = {i["ref"] for i in kev["items"]}
        kev["fixcache"] = {k: v for k, v in cache.items() if k in live}

    async def run_forever(self) -> None:
        while True:
            self.next_refresh_at = int(time.time()) + settings.refresh_seconds
            try:
                await self.refresh()
            except Exception:  # never let the loop die
                log.exception("refresh crashed")
            self._payload = None
            await asyncio.sleep(max(1, self.next_refresh_at - time.time()))

    # -- disk cache --------------------------------------------------------

    def _save(self) -> None:
        try:
            tmp = settings.cache_file.with_suffix(".tmp")
            tmp.write_text(json.dumps({"generated_at": self.generated_at, "state": self._state}))
            tmp.replace(settings.cache_file)
        except OSError as exc:
            log.warning("cache not written: %s", exc)

    def load(self) -> None:
        try:
            data = json.loads(settings.cache_file.read_text())
            for key, st in data["state"].items():
                if key in self._state and isinstance(st.get("items"), list):
                    self._state[key].update(st)
            self.generated_at = int(data["generated_at"])
            self._payload = None
            log.info("loaded cache from %s", settings.cache_file)
        except (OSError, ValueError, KeyError, TypeError):
            pass

    # -- output ------------------------------------------------------------

    def _incidents(self) -> list[dict]:
        """Attacks several sources are reporting right now. See incidents.py."""
        rows = [i for k in INCIDENT_SOURCES for i in self._state[k]["items"]]
        breach = [i for i in rows if "BREACH" in i.get("tags", [])]
        vuln = [i for i in rows if "VULN" in i.get("tags", [])] + self._state["advisories"]["items"]
        return incidents.detect(breach, vuln)

    def payload(self) -> dict:
        if self._payload is None:
            stats: dict[str, int] = {}
            for st in self._state.values():
                stats.update(st["stats"])
            tabs = []
            for key, label, keys in TABS:
                items = [i for k in keys for i in self._state[k]["items"]]
                items.sort(key=lambda i: i.get("ts", 0), reverse=True)
                tabs.append({"key": key, "label": label, "items": items})
            tabs.append({"key": "attacks", "label": "ATTACKS IN THE NEWS", "items": self._incidents()})
            vulns = [i for k in EPSS_SOURCES for i in self._state[k]["items"]]
            stats["fix_open"] = sum(1 for i in vulns if i.get("fix") == "open")
            stats["fix_patched"] = sum(1 for i in vulns if i.get("fix") == "patched")
            stats["fix_unknown"] = sum(1 for i in vulns if i.get("fix") == "unknown")
            self._payload = {
                "generated_at": self.generated_at,
                "next_refresh_at": self.next_refresh_at,
                "refresh_seconds": settings.refresh_seconds,
                "stats": stats,
                "tabs": tabs,
                "sources": [
                    {
                        "key": s.key,
                        "label": s.label,
                        "home": s.home,
                        "ok": self._state[s.key]["ok"],
                        "error": self._state[s.key]["error"],
                        "failed": self._state[s.key].get("failed", []),
                        "fetched_at": self._state[s.key]["fetched_at"],
                        "count": len(self._state[s.key]["items"]),
                    }
                    for s in self.sources
                ],
            }
        return self._payload


feed = Feed()
