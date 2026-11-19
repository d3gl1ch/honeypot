# разбираем события по сессиям и определяем тип атаки
import re
from collections import Counter, defaultdict
from datetime import datetime
from statistics import median

from honeypot.events import AUTH, COMMAND, HTTP_REQUEST
from honeypot.storage.db import Storage

DOWNLOAD_RX = r"\b(wget|curl|tftp|ftpget)\b"  # команды скачивания


def load_sessions(storage):
    # session_id -> список событий по порядку
    sessions = defaultdict(list)
    for e in reversed(storage.get_events(limit=1000000)):  # get_events отдаёт с конца
        sessions[e["session_id"]].append(e)
    return sessions


def classify_session(events):
    http = [e for e in events if e["event_type"] == HTTP_REQUEST]
    auths = [e for e in events if e["event_type"] == AUTH]
    cmds = [e["payload"].get("cmd", "") for e in events if e["event_type"] == COMMAND]

    if http:
        if any(e["payload"].get("attacks") for e in http):
            return "web_attack"
        return "web_probe"
    if len(auths) >= 3:
            return "bruteforce"
    if cmds:
        if any(re.search(DOWNLOAD_RX, c) for c in cmds):
            return "dropper"  # пытался что-то скачать
        return "recon"  # осматривался в системе
    if auths:
        return "failed_login"
    return "scan"  # только подключился и ушёл


def guess_actor(events):
    # бот или человек: смотрим на паузы между действиями
    times = [datetime.fromisoformat(e["ts"]) for e in events
             if e["event_type"] in (AUTH, COMMAND)]
    if len(times) < 3:
        return "unknown"
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    return "bot" if median(gaps) < 3 else "human"


def summarize(storage):
    sessions = load_sessions(storage)
    labels = Counter(classify_session(ev) for ev in sessions.values())
    actors = Counter(guess_actor(ev) for ev in sessions.values())
    return labels, actors


if __name__ == "__main__":
    db = Storage("logs/fake.db")
    labels, actors = summarize(db)
    print("типы сессий:", dict(labels))
    print("бот или человек:", dict(actors))