import asyncio

import aiohttp
import asyncssh

from honeypot.app import start_all
from honeypot.storage.db import Storage


def test_start_all(tmp_path):
    db_path = tmp_path / "t.db"

    async def run():
        ssh, web = await start_all("127.0.0.1", 2297, 8097, str(tmp_path / "key"),
                                   str(db_path), str(tmp_path / "e.jsonl"))
        async with aiohttp.ClientSession() as s:
            await s.get("http://127.0.0.1:8097/admin")
        try:
            await asyncssh.connect("127.0.0.1", 2297, username="root",
                                   password="zzz", known_hosts=None)
        except asyncssh.PermissionDenied:
            pass  # пароль неверный, так и надо
        ssh.close()
        await ssh.wait_closed()
        await web.cleanup()

    asyncio.run(run())
    services = {e["service"] for e in Storage(db_path).get_events(limit=100)}
    assert services == {"ssh", "http"}