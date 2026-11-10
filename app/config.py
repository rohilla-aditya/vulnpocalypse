"""Settings, all optional. The dashboard runs with zero configuration."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "") or default)
    except ValueError:
        return default


@dataclass
class Settings:
    # How often every source is re-scraped. Floor of 5 minutes so a typo can't
    # turn the service into a hammer against other people's feeds.
    refresh_seconds: int = field(default_factory=lambda: max(300, _int("REFRESH_SECONDS", 3600)))
    # Set to 0 to start without the background scraper (tests do this).
    auto_refresh: bool = field(default_factory=lambda: os.getenv("VULN_AUTO_REFRESH", "1") != "0")
    # Optional keys: both APIs work anonymously, a key only raises rate limits.
    nvd_api_key: str = field(default_factory=lambda: os.getenv("NVD_API_KEY", "").strip())
    github_token: str = field(default_factory=lambda: os.getenv("GITHUB_TOKEN", "").strip())
    # SEC EDGAR only answers clients that identify themselves ("Name email").
    # The SEC breach-disclosure source is skipped while this is empty.
    sec_user_agent: str = field(default_factory=lambda: os.getenv("SEC_USER_AGENT", "").strip())
    # Canonical public URL for the social-card tags. Render sets
    # RENDER_EXTERNAL_URL on its own; PUBLIC_URL overrides it (custom domain).
    public_url: str = field(
        default_factory=lambda: (os.getenv("PUBLIC_URL") or os.getenv("RENDER_EXTERNAL_URL") or "").strip().rstrip("/")
    )
    # Last good scrape is kept on disk so a restart serves data immediately.
    cache_file: Path = field(
        default_factory=lambda: Path(os.getenv("VULN_CACHE_FILE") or Path(tempfile.gettempdir()) / "vuln-pocalypse-cache.json")
    )


settings = Settings()
