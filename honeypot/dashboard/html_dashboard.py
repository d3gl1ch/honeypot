# дашборд: один html файл с графиками, без библиотек
import argparse
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from honeypot.analysis import ioc, mitre, sessions, stats
from honeypot.events import HTTP_REQUEST
from honeypot.storage.db import Storage

STYLE = """
body{font-family:Segoe UI,Arial,sans-serif;background:#0f1419;color:#e6e6e6;margin:0;padding:20px}
h1{margin:0 0 4px}
.sub{color:#8b949e;margin-bottom:20px}
.nums{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.num-card{background:#1a2029;border-radius:8px;padding:12px 20px}
.num-card b{display:block;font-size:26px}
.num-card span{color:#8b949e;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:16px}
.card{background:#1a2029;border-radius:8px;padding:14px}
.card h3{margin:0 0 10px;font-size:15px}
.row{display:flex;align-items:center;gap:8px;margin:4px 0;font-size:13px}
.name{width:40%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:Consolas,monospace}
.bar{flex:1;background:#232b36;height:12px;border-radius:6px;overflow:hidden}
.bar span{display:block;height:100%;background:#3b82f6}
.num{width:50px;text-align:right}
.empty{color:#8b949e}
"""


def number_card(label, value):
    return (f"<div class='num-card'><b>{escape(str(value))}</b>"
            f"<span>{escape(label)}</span></div>")


def bar_chart(title, rows):
    # rows: список (название, число)
    # все что пришло от атакующих экранируем, иначе в страницу можно вставить скрипт
    out = [f"<div class='card'><h3>{escape(title)}</h3>"]
    if not rows:
        out.append("<p class='empty'>нет данных</p>")
    else:
        biggest = max(n for _, n in rows) or 1
        for name, n in rows:
            width = max(round(n * 100 / biggest), 1)
            name = escape(str(name))
            out.append(f"<div class='row'><span class='name' title=\"{name}\">{name}</span>"
                       f"<span class='bar'><span style='width:{width}%'></span></span>"
                       f"<span class='num'>{n}</span></div>")
    out.append("</div>")
    return "\n".join(out)


def page(body):
    return ("<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
            "<title>Honeypot</title><style>" + STYLE + "</style></head><body>"
            + body + "</body></html>")


def build_html(storage, top=10):
    events = storage.get_events(limit=1000000)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    head = f"<h1>Honeypot</h1><div class='sub'>обновлено {now} UTC"

    if not events:
        return page(head + "</div><p>Событий пока нет.</p>")

    times = [e["ts"] for e in events]
    head += f", период {min(times)[:10]} - {max(times)[:10]}</div>"

    labels, actors = sessions.summarize(storage)
    techs, tactics = mitre.summarize(storage)
    found = ioc.collect(storage)

    web = Counter()
    for e in storage.get_events(event_type=HTTP_REQUEST, limit=1000000):
        web.update(e["payload"].get("attacks", []))

    nums = "".join([
        number_card("событий", len(events)),
        number_card("сессий", len(sessions.load_sessions(storage))),
        number_card("уникальных ip", len(storage.count_by("src_ip"))),
        number_card("ip в блоклисте", len(ioc.bad_ips(storage))),
    ])

    tech_rows = [(f"{t} {mitre.TECHNIQUES[t][0]}", n) for t, n in techs.most_common(top)]
    charts = [
        bar_chart("События по сервисам",
                  [(r["value"], r["cnt"]) for r in storage.count_by("service")]),
        bar_chart("Типы сессий", labels.most_common()),
        bar_chart("Бот или человек", actors.most_common()),
        bar_chart("Топ IP", stats.top_ips(storage, top)),
        bar_chart("Топ логинов (SSH)", stats.top_payload(storage, "auth", "user", top)),
        bar_chart("Топ паролей (SSH)", stats.top_payload(storage, "auth", "password", top)),
        bar_chart("Топ команд", stats.top_payload(storage, "command", "cmd", top)),
        bar_chart("Веб-атаки", web.most_common()),
        bar_chart("События по дням (последние 14)", stats.events_per_day(storage)[-14:]),
        bar_chart("MITRE: тактики", tactics.most_common()),
        bar_chart("MITRE: техники", tech_rows),
        bar_chart("IoC: домены", found["domains"].most_common(top)),
        bar_chart("IoC: URL", found["urls"].most_common(top)),
    ]
    return page(head + f"<div class='nums'>{nums}</div>"
                f"<div class='grid'>{''.join(charts)}</div>")


def save_dashboard(storage, path="logs/dashboard.html"):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(build_html(storage), encoding="utf-8")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--db", default="logs/fake.db")
    p.add_argument("--out", default="logs/dashboard.html")
    args = p.parse_args()
    save_dashboard(Storage(args.db), args.out)
    print("дашборд сохранён:", args.out)