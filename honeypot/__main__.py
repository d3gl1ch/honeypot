# запуск: python -m honeypot
import argparse
import asyncio

from honeypot.app import start_all
from honeypot.config import load_config


def parse_args():
    p = argparse.ArgumentParser(description="honeypot")
    p.add_argument("--config", default="configs/settings.json")
    p.add_argument("--host", default=None)
    p.add_argument("--ssh-port", type=int, default=None)
    p.add_argument("--http-port", type=int, default=None)
    p.add_argument("--key", default=None)
    p.add_argument("--db", default=None)
    p.add_argument("--log", default=None)
    p.add_argument("--quarantine", default=None)
    p.add_argument("--telnet-port", type=int, default=None)
    return p.parse_args()


def pick(value, default):
    # флаг из командной строки важнее конфига
    return default if value is None else value


async def run(args):
    cfg = load_config(args.config)
    host = pick(args.host, cfg["host"])
    ssh_port = pick(args.ssh_port, cfg["ports"]["ssh"])
    http_port = pick(args.http_port, cfg["ports"]["http"])
    key_path = pick(args.key, cfg["paths"]["ssh_key"])
    db_path = pick(args.db, cfg["paths"]["db"])
    log_path = pick(args.log, cfg["paths"]["log"])
    quarantine_path = pick(args.quarantine, cfg["paths"]["quarantine"])
    telnet_port = pick(args.telnet_port, cfg["ports"]["telnet"])

    ssh, web, telnet = await start_all(host, ssh_port, http_port, key_path,
                                       db_path, log_path, quarantine_path,
                                       telnet_port, config=cfg)
    print(f"ssh {ssh_port}, http {http_port}, telnet {telnet_port}")
    try:
        await asyncio.Event().wait()  # висим пока не остановим
    finally:
        ssh.close()
        await ssh.wait_closed()
        await web.cleanup()
        if telnet:
            telnet.close()
            await telnet.wait_closed()