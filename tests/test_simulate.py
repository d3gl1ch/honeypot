import asyncio

from honeypot.app import start_all
from honeypot.simulate import simulate
from honeypot.storage.db import Storage


def test_simulate(tmp_path):
    db_path = tmp_path / "t.db"

    async def run():
        ssh, web = await start_all("127.0.0.1", 2296, 8096, str(tmp_path / "key"),
                                   str(db_path), str(tmp_path / "e.jsonl"))
        result = await simulate(2296, 8096, scans=2, brutes=1, attempts=3,
                                bots=1, humans=0, webs=2, one_ip=True)
        ssh.close()
        await ssh.wait_closed()
        await web.cleanup()
        return result

    ok, total = asyncio.run(run())
    assert ok == total

    db = Storage(db_path)
    assert {e["service"] for e in db.get_events(limit=1000)} == {"ssh", "http"}

    auths = db.get_events(event_type="auth", limit=1000)
    assert any(e["payload"]["success"] for e in auths)       # бот зашел
    assert any(not e["payload"]["success"] for e in auths)   # были и неудачи
    assert db.get_events(event_type="command")               # команды записались

    web_events = db.get_events(event_type="http_request", limit=1000)
    assert any(e["payload"]["attacks"] for e in web_events)  # веб-атаки найдены