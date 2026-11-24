# telnet-приманка: просит логин/пароль и пускает в поддельную консоль
import asyncio

from honeypot.events import Event, CONNECT, AUTH, COMMAND, DISCONNECT
from honeypot.logger import EventLogger
from honeypot.sensors.ssh_server import drain_downloads
from honeypot.shell.fake_shell import FakeShell
from honeypot.storage.db import Storage

WEAK_PASSWORDS = {"123456", "admin", "password", "root", "1234", "qwerty"}
IAC = 255
IDLE_TIMEOUT = 60


def strip_iac(data):
    # выкидываем telnet-команды (IAC ...), оставляем только текст
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == IAC and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd == IAC:
                out.append(IAC)
                i += 2
            elif cmd in (251, 252, 253, 254):  # WILL WONT DO DONT
                i += 3
            else:
                i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out)


async def read_line(reader, timeout):
    try:
        data = await asyncio.wait_for(reader.readline(), timeout)
    except asyncio.TimeoutError:
        return None
    return strip_iac(data).decode("utf-8", "replace").strip()


async def handle(reader, writer, logger, quarantine_path, idle_timeout,
                 passwords):
    peer = writer.get_extra_info("peername") or ("?", 0)
    ip, port = peer[0], peer[1]
    ev = Event("telnet", CONNECT, ip, port)
    sid = ev.session_id
    logger.log(ev)

    try:
        writer.write(b"Ubuntu 22.04.3 LTS srv01\r\n\r\nlogin: ")
        await writer.drain()
        user = await read_line(reader, idle_timeout)
        if user is None:
            return

        writer.write(b"Password: ")
        await writer.drain()
        password = await read_line(reader, idle_timeout)
        if password is None:
            return

        ok = password in passwords
        logger.log(Event("telnet", AUTH, ip, port, session_id=sid,
                         payload={"user": user, "password": password,
                                  "success": ok}))
        if not ok:
            writer.write(b"\r\nLogin incorrect\r\n")
            await writer.drain()
            return

        shell = FakeShell(user or "root")
        writer.write(b"\r\nWelcome to Ubuntu 22.04.3 LTS\r\n\r\n")
        await writer.drain()
        while not shell.closed:
            writer.write((shell.prompt() + " ").encode())
            await writer.drain()
            line = await read_line(reader, idle_timeout)
            if line is None or not line:
                break
            logger.log(Event("telnet", COMMAND, ip, port, session_id=sid,
                             payload={"cmd": line}))
            writer.write(shell.run(line).encode())
            await writer.drain()
            drain_downloads(shell, logger, ip, port, sid, quarantine_path,
                            service="telnet")
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        logger.log(Event("telnet", DISCONNECT, ip, port, session_id=sid))
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, asyncio.TimeoutError):
            pass


async def start_server(host="0.0.0.0", port=2323, db_path="logs/events.db",
                       log_path="logs/events.jsonl", quarantine_path="quarantine",
                       idle_timeout=IDLE_TIMEOUT, weak_passwords=None):
    logger = EventLogger(log_path, storage=Storage(db_path))
    passwords = WEAK_PASSWORDS if weak_passwords is None else weak_passwords

    async def handler(reader, writer):
        await handle(reader, writer, logger, quarantine_path, idle_timeout,
                     passwords)

    return await asyncio.start_server(handler, host, port)