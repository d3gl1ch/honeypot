# достаём индикаторы компрометации (ioc) из событий
import re
from collections import Counter
from pathlib import Path
from urllib.parse import unquote_plus

from honeypot.analysis.sessions import load_sessions, classify_session
from honeypot.events import COMMAND, HTTP_REQUEST
from honeypot.storage.db import Storage

URL_RX = re.compile(r"(?:https?|ftp)://[^\s'\"<>|;]+")
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RX = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")

# какие типы сессий считаем опасными для блоклиста
BAD_TYPES = {"bruteforce", "recon", "dropper", "web_attack"}


def valid_ip(s):
    return all(int(p) <= 255 for p in s.split("."))


def host_of(url):
    # http://host:port/path -> host
    return url.split("//", 1)[1].split("/", 1)[0].split(":")[0].lower()


def extract_iocs(text):
    urls = set(URL_RX.findall(text))
    ips = {ip for ip in IP_RX.findall(text) if valid_ip(ip)}
    hashes = {h.lower() for h in HASH_RX.findall(text)}
    domains = set()
    for u in urls:
        host = host_of(u)
        if not IP_RX.fullmatch(host):  # если вместо домена ip, не считаем
            domains.add(host)
    return {"urls": urls, "ips": ips, "domains": domains, "hashes": hashes}


def collect(storage):
    # считаем, сколько раз встретился каждый индикатор
    counts = {"urls": Counter(), "ips": Counter(), "domains": Counter(), "hashes": Counter()}
    for e in storage.get_events(limit=1000000):
        p = e["payload"]
        if e["event_type"] == COMMAND:
            text = p.get("cmd", "")
        elif e["event_type"] == HTTP_REQUEST:
            text = f'{p.get("path", "")} {p.get("query", "")} {p.get("body", "")}'
        else:
            continue
        found = extract_iocs(unquote_plus(text))
        for kind, values in found.items():
            counts[kind].update(values)
    return counts


def bad_ips(storage):
    # ip тех, кто делал что-то опасное
    ips = set()
    for events in load_sessions(storage).values():
        if classify_session(events) in BAD_TYPES:
            ips.add(events[0]["src_ip"])
    return sorted(ips)


def save_blocklist(storage, path="logs/blocklist.txt"):
    ips = bad_ips(storage)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("".join(ip + "\n" for ip in ips), encoding="utf-8")
    return len(ips)


if __name__ == "__main__":
    db = Storage("logs/fake.db")
    for kind, c in collect(db).items():
        print(kind, c.most_common(5))
    print("ip в блоклисте:", save_blocklist(db))