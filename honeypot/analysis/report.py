# автоотчет в markdown из собранных событий
import argparse
from collections import Counter
from pathlib import Path

from honeypot.analysis import ioc, mitre, sessions, stats
from honeypot.enrich import geoip
from honeypot.events import HTTP_REQUEST
from honeypot.storage.db import Storage


def cell(value):
    # чтобы | и переводы строк не ломали таблицу
    return str(value).replace("|", "\\|").replace("\n", " ")


def table(headers, rows):
    if not rows:
        return "нет данных\n"
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "---|" * len(headers)]
    for r in rows:
        lines.append("| " + " | ".join(cell(x) for x in r) + " |")
    return "\n".join(lines) + "\n"


def section(out, title, headers, rows):
    out.append(f"## {title}\n")
    out.append(table(headers, rows))


def build_report(storage, top=10):
    events = storage.get_events(limit=1000000)
    out = ["# Отчёт honeypot\n"]
    if not events:
        out.append("Событий пока нет.\n")
        return "\n".join(out)

    times = [e["ts"] for e in events]
    labels, actors = sessions.summarize(storage)
    techs, tactics = mitre.summarize(storage)
    found = ioc.collect(storage)

    out.append(f"- Период: {min(times)[:19]} - {max(times)[:19]} (UTC)")
    out.append(f"- Всего событий: {len(events)}")
    out.append(f"- Сессий: {len(sessions.load_sessions(storage))}")
    out.append(f"- Уникальных IP: {len(storage.count_by('src_ip'))}")
    out.append(f"- IP в блоклисте: {len(ioc.bad_ips(storage))}\n")

    section(out, "События по сервисам", ["Сервис", "Событий"],
            [(r["value"], r["cnt"]) for r in storage.count_by("service")])
    section(out, "Типы сессий", ["Тип", "Сессий"], labels.most_common())
    section(out, "Бот или человек", ["Кто", "Сессий"], actors.most_common())
    section(out, "Топ IP", ["IP", "Событий"], stats.top_ips(storage, top))
    geo_rows = []
    for row in storage.count_by("src_ip")[:top]:
        info = geoip.lookup(row["value"])
        geo_rows.append((row["value"], info["country"], info["asn"],
                         info["org"], row["cnt"]))
    section(out, "География IP", ["IP", "Страна", "ASN", "Провайдер", "Событий"],
            geo_rows)
    section(out, "Страны", ["Страна", "Событий"],
            geoip.count_by(events).most_common())
    section(out, "Провайдеры", ["Провайдер", "Событий"],
            geoip.count_by(events, "org").most_common())
    brute = [(ip, n) for ip, n in sessions.failed_auth_by_ip(storage).most_common()
             if n >= 3]
    section(out, "IP с перебором паролей", ["IP", "Неудачных входов"], brute[:top])
    section(out, "Топ логинов (SSH)", ["Логин", "Попыток"],
            stats.top_payload(storage, "auth", "user", top))
    section(out, "Топ паролей (SSH)", ["Пароль", "Попыток"],
            stats.top_payload(storage, "auth", "password", top))
    section(out, "Топ команд", ["Команда", "Раз"],
            stats.top_payload(storage, "command", "cmd", top))

    # веб-атаки по типам
    web = Counter()
    for e in storage.get_events(event_type=HTTP_REQUEST, limit=1000000):
        web.update(e["payload"].get("attacks", []))
    section(out, "Веб-атаки", ["Тип", "Запросов"], web.most_common())

    section(out, "События по дням", ["День", "Событий"], stats.events_per_day(storage))

    section(out, "IoC: URL", ["URL", "Раз"], found["urls"].most_common(top))
    section(out, "IoC: домены", ["Домен", "Раз"], found["domains"].most_common(top))
    section(out, "IoC: IP из команд", ["IP", "Раз"], found["ips"].most_common(top))
    section(out, "IoC: хэши", ["Хэш", "Раз"], found["hashes"].most_common(top))

    rows = [(tid, mitre.TECHNIQUES[tid][0], mitre.TECHNIQUES[tid][1], n)
            for tid, n in techs.most_common()]
    section(out, "MITRE ATT&CK", ["ID", "Техника", "Тактика", "Сессий"], rows)
    section(out, "MITRE: тактики", ["Тактика", "Срабатываний"], tactics.most_common())

    return "\n".join(out)


def save_report(storage, path="logs/report.md"):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(build_report(storage), encoding="utf-8")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--db", default="logs/fake.db")
    p.add_argument("--out", default="logs/report.md")
    args = p.parse_args()
    save_report(Storage(args.db), args.out)
    print("отчёт сохранён:", args.out)