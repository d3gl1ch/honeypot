import asyncio

import aiohttp

from honeypot.sensors.http_server import start_server, detect_attacks
from honeypot.storage.db import Storage


def test_detect_attacks():
    assert "sqli" in detect_attacks("/?id=1' or 1=1")
    assert "traversal" in detect_attacks("/../../etc/passwd")
    assert "xss" in detect_attacks("<script>alert(1)</script>")
    assert detect_attacks("/index.html") == []


def test_http_logs(tmp_path):
    db_path = tmp_path / "t.db"
    url = "http://127.0.0.1:8099"

    async def run():
        runner = await start_server(host="127.0.0.1", port=8099,
                                    db_path=str(db_path),
                                    log_path=str(tmp_path / "e.jsonl"))
        async with aiohttp.ClientSession() as s:
            page = await (await s.get(url + "/admin")).text()
            r = await s.post(url + "/login",
                             data={"username": "admin", "password": "qwerty"})
            await s.get(url + "/", params={"id": "1' or 1=1"})
        await runner.cleanup()
        return page, r.status

    page, status = asyncio.run(run())
    assert "Admin panel" in page
    assert status == 401

    events = Storage(db_path).get_events(event_type="http_request")
    login = [e for e in events if e["payload"]["path"] == "/login"][0]
    assert login["payload"]["user"] == "admin"
    assert login["payload"]["password"] == "qwerty"
    assert any("sqli" in e["payload"]["attacks"] for e in events)