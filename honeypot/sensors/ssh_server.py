# ssh приманка: принимает любые подключения и пишет логины/пароли
import asyncio
from pathlib import Path

import asyncssh

from honeypot.events import Event, CONNECT, AUTH, DISCONNECT
from honeypot.logger import EventLogger
from honeypot.storage.db import Storage


class HoneySSHServer(asyncssh.SSHServer):
    def __init__(self, logger):
        self.logger = logger
        self.ip = "?"
        self.port = 0
        self.session_id = None

    def connection_made(self, conn):
        # кто подключился
        self.ip, self.port = conn.get_extra_info("peername")[:2]
        ev = Event("ssh", CONNECT, self.ip, self.port)
        self.session_id = ev.session_id
        self.logger.log(ev)

    def connection_lost(self, exc):
        self.logger.log(Event("ssh", DISCONNECT, self.ip, self.port,
                              session_id=self.session_id))

    def begin_auth(self, username):
        return True  # требуем авторизацию

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self.logger.log(Event("ssh", AUTH, self.ip, self.port,
                              session_id=self.session_id,
                              payload={"user": username, "password": password}))
        return False  # пока никого не пускаем


def get_host_key(path):
    # ключ сервера: если нет файла, создаём
    p = Path(path)
    if p.exists():
        return asyncssh.read_private_key(str(p))
    key = asyncssh.generate_private_key("ssh-rsa")
    key.write_private_key(str(p))
    return key


async def start_server(host="0.0.0.0", port=2222, key_path="keys/ssh_host_key",
                       db_path="logs/events.db", log_path="logs/events.jsonl"):
    Path(key_path).parent.mkdir(parents=True, exist_ok=True)
    key = get_host_key(key_path)
    logger = EventLogger(log_path, storage=Storage(db_path))
    return await asyncssh.listen(host, port,
                                 server_factory=lambda: HoneySSHServer(logger),
                                 server_host_keys=[key])


async def main():
    await start_server()
    print("ssh honeypot слушает порт 2222")
    await asyncio.Event().wait()  # висим пока не остановим


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("стоп")