import os

os.environ["VULN_AUTO_REFRESH"] = "0"

from fastapi.testclient import TestClient

from app.main import app


def test_health_feed_and_index():
    with TestClient(app) as c:
        assert c.get("/api/health").json()["ok"] is True
        feed = c.get("/api/feed")
        assert feed.status_code == 200 and len(feed.json()["tabs"]) == 8
        page = c.get("/", headers={"host": "example.test"})
        assert page.status_code == 200
        assert "__BASE_URL__" not in page.text
        assert 'content="http://example.test/og.png"' in page.text
        assert "script-src 'self'" in page.headers["content-security-policy"]
        assert c.get("/feed.json").json()["tabs"] == feed.json()["tabs"]
        assert c.get("/app.js").status_code == 200
        assert c.get("/docs").status_code == 404
