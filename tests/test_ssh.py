import asyncio
import asyncssh

from honeypot.sensors.ssh_server import start_server
from honeypot.storage.db import Storage


def test_ssh_logs_password(tmp_path):
    db_path = tmp_path / "t.db"

    async def run():
        server = await start_server(port=2299, key_path=str(tmp_path / "key"),
                                    db_path=str(db_path),
                                    log_path=str(tmp_path / "e.jsonl"))
        try:
            await asyncssh.connect("127.0.0.1", 2299, username="root",
                                   password="1234", known_hosts=None)
        except asyncssh.PermissionDenied:
            pass  # так и должно быть, мы никого не пускаем
        server.close()
        await server.wait_closed()

    asyncio.run(run())

    auth = Storage(db_path).get_events(event_type="auth")
    assert auth[0]["payload"]["user"] == "root"
    assert auth[0]["payload"]["password"] == "1234"