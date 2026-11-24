from honeypot.events import Event, AUTH, COMMAND
from honeypot.storage.db import Storage
from honeypot.dashboard.html_dashboard import build_html, bar_chart, save_dashboard


def make_db(tmp_path):
    db = Storage(tmp_path / "t.db")
    for _ in range(3):
        db.save(Event("ssh", AUTH, "1.1.1.1", session_id="a",
                      payload={"user": "root", "password": "<script>alert(1)</script>"}))
    db.save(Event("ssh", COMMAND, "1.1.1.1", session_id="a",
                  payload={"cmd": "<img src=x onerror=alert(1)>"}))
    return db


def test_bar_chart():
    html = bar_chart("тест", [("a", 10), ("b", 5)])
    assert "width:100%" in html
    assert "width:50%" in html
    assert "нет данных" in bar_chart("тест", [])


def test_escape(tmp_path):
    html = build_html(make_db(tmp_path))
    assert "<script" not in html      # скрипт из пароля не должен попасть как тег
    assert "<img" not in html
    assert "&lt;script&gt;" in html   # а как текст должен


def test_empty(tmp_path):
    assert "Событий пока нет" in build_html(Storage(tmp_path / "e.db"))


def test_save(tmp_path):
    path = tmp_path / "out" / "d.html"
    save_dashboard(make_db(tmp_path), path)
    assert path.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_enrich_cards(tmp_path):
    html = build_html(make_db(tmp_path))
    assert "Страны" in html
    assert "Провайдеры" in html


def test_content(tmp_path):
    html = build_html(make_db(tmp_path))
    assert "Топ паролей" in html
    assert "bruteforce" in html