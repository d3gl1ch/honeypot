import json
from honeypot.events import Event, AUTH
from honeypot.logger import EventLogger


def test_log_event(tmp_path):
    p = tmp_path / "e.jsonl"
    ev = Event("ssh", AUTH, "1.2.3.4", payload={"user": "root", "password": "123"})
    EventLogger(p).log(ev)

    line = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
    assert line["service"] == "ssh"
    assert line["payload"]["user"] == "root"