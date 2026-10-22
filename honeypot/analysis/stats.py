# простая статистика по событиям
from collections import Counter

from honeypot.storage.db import Storage


def top_ips(storage, n=5):
    return [(r["value"], r["cnt"]) for r in storage.count_by("src_ip")[:n]]


def top_payload(storage, event_type, key, n=5):
    # самые частые значения из payload, например пароли из auth
    events = storage.get_events(event_type=event_type, limit=1000000)
    return Counter(e["payload"].get(key) for e in events).most_common(n)


def events_per_day(storage):
    events = storage.get_events(limit=1000000)
    days = Counter(e["ts"][:10] for e in events)
    return sorted(days.items())


if __name__ == "__main__":
    db = Storage("logs/fake.db")
    print("топ ip:", top_ips(db))
    print("топ логинов:", top_payload(db, "auth", "user"))
    print("топ паролей:", top_payload(db, "auth", "password"))
    print("топ команд:", top_payload(db, "command", "cmd"))
    print("по дням:", events_per_day(db))