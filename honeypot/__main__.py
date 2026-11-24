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
    p.add_argument("--telnet-port", type=int, default=2323)
    return p.parse_args()


async def run(args):
    ssh, web, telnet = await start_all(args.host, args.ssh_port, args.http_port,
                                       args.key, args.db, args.log,
                                       args.quarantine, args.telnet_port)
    print(f"ssh {args.ssh_port}, http {args.http_port}, telnet {args.telnet_port}")
    try:
        await asyncio.Event().wait()  # висим пока не остановим
    finally:
        ssh.close()
        await ssh.wait_closed()
        await web.cleanup()
        if telnet:
            telnet.close()
            await telnet.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(run(parse_args()))
    except KeyboardInterrupt:
        print("стоп")