# ssh приманка: слабые пароли пускают в поддельную консоль
import asyncio
from pathlib import Path

import asyncssh

from honeypot.events import Event, CONNECT, AUTH, COMMAND, DISCONNECT
from honeypot.logger import EventLogger
from honeypot.shell.fake_shell import FakeShell
from honeypot.storage.db import Storage
from honeypot.events import Event, CONNECT, AUTH, COMMAND, DOWNLOAD, DISCONNECT

# с этими паролями "взлом" удаётся
WEAK_PASSWORDS = {"123456", "admin", "password", "root", "1234", "qwerty"}

# (ip, port) -> session_id, чтобы команды попадали в ту же сессию
SESSIONS = {}

MAX_CONNECTIONS = 100   # одновременно открытых ssh-сессий
MAX_AUTH_TRIES = 5      # попыток пароля на одно соединение
IDLE_TIMEOUT = 60       # секунд без команд, потом отключаем
SERVER_VERSION = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"


class HoneySSHServer(asyncssh.SSHServer):
    def __init__(self, logger):
        self.logger = logger
        self.conn = None
        self.auth_tries = 0
        self.ip = "?"
        self.port = 0
        self.session_id = None

    def connection_made(self, conn):
        # кто подключился
        self.conn = conn
        self.ip, self.port = conn.get_extra_info("peername")[:2]
        client_version = conn.get_extra_info("client_version") or ""
        ev = Event("ssh", CONNECT, self.ip, self.port,
                   payload={"client_version": client_version})
        self.session_id = ev.session_id
        SESSIONS[(self.ip, self.port)] = self.session_id
        self.logger.log(ev)
        if len(SESSIONS) > MAX_CONNECTIONS:
            conn.close()  # слишком много соединений, не пускаем

    def connection_lost(self, exc):
        SESSIONS.pop((self.ip, self.port), None)
        self.logger.log(Event("ssh", DISCONNECT, self.ip, self.port,
                              session_id=self.session_id))

    def begin_auth(self, username):
        return True  # требуем авторизацию

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self.auth_tries += 1
        ok = password in WEAK_PASSWORDS
        self.logger.log(Event("ssh", AUTH, self.ip, self.port,
                              session_id=self.session_id,
                              payload={"user": username, "password": password,
                                       "success": ok,
                                       "attempt": self.auth_tries,
                                       "client_version": self.conn.get_extra_info(
                                           "client_version") or ""}))
        if not ok and self.auth_tries >= MAX_AUTH_TRIES:
            self.conn.close()  # хватит перебирать пароли
        return ok


def drain_downloads(shell, logger, ip, port, sid, quarantine_path):
    # логируем загрузку и кладём заглушку в карантин
    if not shell.downloads:
        return
    for d in shell.downloads:
        payload = {"url": d["url"], "name": d["name"], "sha256": d["sha256"]}
        if quarantine_path:
            qdir = Path(quarantine_path)
            qdir.mkdir(parents=True, exist_ok=True)
            prefix = (sid or "na")[:8]
            qfile = qdir / f"{prefix}_{d['name']}"
            qfile.write_text(d["content"], encoding="utf-8")
            payload["path"] = str(qfile)
        logger.log(Event("ssh", DOWNLOAD, ip, port, session_id=sid,
                         payload=payload))
    shell.downloads.clear()


async def handle_session(process, logger, quarantine_path=None,
                         idle_timeout=IDLE_TIMEOUT):
    # работа атакующего внутри поддельной консоли
    ip, port = process.get_extra_info("peername")[:2]
    sid = SESSIONS.get((ip, port))
    shell = FakeShell(process.get_extra_info("username"))

    def log_cmd(line):
        logger.log(Event("ssh", COMMAND, ip, port, session_id=sid,
                         payload={"cmd": line}))

    # ssh host команда, так часто делают боты
    if process.command:
        log_cmd(process.command)
        process.stdout.write(shell.run(process.command))
        drain_downloads(shell, logger, ip, port, sid, quarantine_path)
        process.exit(0)
        return

    process.stdout.write("Welcome to Ubuntu 22.04.3 LTS\n\n")
    while not shell.closed:
        process.stdout.write(shell.prompt())
        try:
            line = await asyncio.wait_for(process.stdin.readline(), idle_timeout)
        except asyncio.TimeoutError:
            process.stdout.write("\nConnection timed out.\n")
            break
        except asyncssh.BreakReceived:
            process.stdout.write("\n")
            continue
        if not line:  # клиент отключился
            break
        line = line.strip()
        if line:
            log_cmd(line)
            process.stdout.write(shell.run(line))
            drain_downloads(shell, logger, ip, port, sid, quarantine_path)
    process.exit(0)


def get_host_key(path):
    # ключ сервера: если нет файла, создаём
    p = Path(path)
    if p.exists():
        return asyncssh.read_private_key(str(p))
    key = asyncssh.generate_private_key("ssh-rsa")
    key.write_private_key(str(p))
    return key


async def start_server(host="0.0.0.0", port=2222, key_path="keys/ssh_host_key",
                       db_path="logs/events.db", log_path="logs/events.jsonl",
                        quarantine_path="quarantine", idle_timeout=IDLE_TIMEOUT):
    Path(key_path).parent.mkdir(parents=True, exist_ok=True)
    key = get_host_key(key_path)
    logger = EventLogger(log_path, storage=Storage(db_path))

    async def handler(process):
        await handle_session(process, logger, quarantine_path, idle_timeout)

    return await asyncssh.listen(host, port,
                                 server_factory=lambda: HoneySSHServer(logger),
                                 server_host_keys=[key],
                                 process_factory=handler,
                                 server_version=SERVER_VERSION,
                                 login_timeout=30)


async def main():
    await start_server()
    print("ssh honeypot слушает порт 2222")
    await asyncio.Event().wait()  # висим пока не остановим


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("стоп")