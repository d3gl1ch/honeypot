import asyncio

from honeypot.sensors.telnet_server import start_server, strip_iac
from honeypot.storage.db import Storage


def test_strip_iac():
    assert strip_iac(b"\xff\xfb\x01root\r\n") == b"root\r\n"
    assert strip_iac(b"a\xff\xffb") == b"a\xffb"


def chat(tmp_path, port, payload):
    db_path = tmp_path / "t.db"

    async def run():
        server = await start_server(port=port, db_path=str(db_path),
                                    log_path=str(tmp_path / "e.jsonl"),
                                    quarantine_path=str(tmp_path / "quarantine"),
                                    idle_timeout=5)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(payload)
        await writer.drain()
        data = b""
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), 2)
                if not chunk:
                    break
                data += chunk
        except (asyncio.TimeoutError, ConnectionError):
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass
        server.close()
        await server.wait_closed()
        return data

    return db_path, asyncio.run(run())


def test_telnet_login_and_command(tmp_path):
    db_path, out = chat(tmp_path, 2399, b"root\r\n123456\r\nwhoami\r\nexit\r\n")
    assert b"login:" in out.lower()
    auth = Storage(db_path).get_events(service="telnet", event_type="auth")
    assert auth[0]["payload"]["success"] is True
    cmds = Storage(db_path).get_events(service="telnet", event_type="command")
    assert "whoami" in [c["payload"]["cmd"] for c in cmds]


def test_telnet_bad_password(tmp_path):
    db_path, out = chat(tmp_path, 2398, b"root\r\nwrongpass\r\n")
    assert b"Login incorrect" in out
    auth = Storage(db_path).get_events(service="telnet", event_type="auth")
    assert auth[0]["payload"]["success"] is False