import pytest
from honeypot.events import Event, AUTH, COMMAND
from honeypot.storage.db import Storage


def test_save_and_get(tmp_path):
    db = Storage(tmp_path / "t.db")
    db.save(Event("ssh", AUTH, "1.1.1.1", payload={"user": "root", "password": "123"}))
    db.save(Event("ssh", COMMAND, "1.1.1.1", payload={"cmd": "ls"}))
    db.save(Event("http", AUTH, "2.2.2.2"))

    assert len(db.get_events()) == 3
    assert len(db.get_events(service="http")) == 1
    assert db.get_events(event_type=COMMAND)[0]["payload"]["cmd"] == "ls"
    db.close()


def test_count_by(tmp_path):
    db = Storage(tmp_path / "t.db")
    for _ in range(3):
        db.save(Event("ssh", AUTH, "1.1.1.1"))
    db.save(Event("ssh", AUTH, "2.2.2.2"))

    top = db.count_by("src_ip")
    assert top[0] == {"value": "1.1.1.1", "cnt": 3}
    db.close()


def test_bad_column(tmp_path):
    db = Storage(tmp_path / "t.db")
    with pytest.raises(ValueError):
        db.count_by("payload; DROP TABLE events")
    db.close()