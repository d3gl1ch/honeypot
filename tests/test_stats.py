from honeypot.events import Event, AUTH
from honeypot.storage.db import Storage
from honeypot.analysis.stats import top_ips, top_payload


def make_db(tmp_path):
    db = Storage(tmp_path / "t.db")
    for pw in ["123", "123", "admin"]:
        db.save(Event("ssh", AUTH, "1.1.1.1", payload={"user": "root", "password": pw}))
    db.save(Event("ssh", AUTH, "2.2.2.2", payload={"user": "pi", "password": "123"}))
    return db


def test_top_ips(tmp_path):
    assert top_ips(make_db(tmp_path))[0] == ("1.1.1.1", 3)


def test_top_passwords(tmp_path):
    assert top_payload(make_db(tmp_path), "auth", "password")[0] == ("123", 3)