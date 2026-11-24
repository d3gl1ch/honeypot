# запуск: python -m honeypot
import argparse
import asyncio

from honeypot.app import start_all


def parse_args():
    p = argparse.ArgumentParser(description="honeypot")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--ssh-port", type=int, default=2222)
    p.add_argument("--http-port", type=int, default=8080)
    p.add_argument("--key", default="keys/ssh_host_key")
    p.add_argument("--db", default="logs/events.db")
    p.add_argument("--log", default="logs/events.jsonl")
    p.add_argument("--quarantine", default="quarantine")
    return p.parse_args()


async def run(args):
    ssh, web = await start_all(args.host, args.ssh_port, args.http_port,
                               args.key, args.db, args.log, args.quarantine)
    print(f"ssh на порту {args.ssh_port}, http на порту {args.http_port}")
    try:
        await asyncio.Event().wait()  # висим пока не остановим
    finally:
        ssh.close()
        await ssh.wait_closed()
        await web.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(run(parse_args()))
    except KeyboardInterrupt:
        print("стоп")