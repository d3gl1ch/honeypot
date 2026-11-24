import json

from honeypot.config import load_config


def test_defaults_without_file(tmp_path):
    cfg = load_config(tmp_path / "nope.json")
    assert cfg["ports"]["ssh"] == 2222
    assert "123456" in cfg["ssh"]["weak_passwords"]


def test_deep_merge(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"ports": {"ssh": 2200}}), encoding="utf-8")
    cfg = load_config(path)
    assert cfg["ports"]["ssh"] == 2200
    assert cfg["ports"]["http"] == 8080  # осталось из значений по умолчанию


def test_bad_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{oops", encoding="utf-8")
    try:
        load_config(path)
    except ValueError:
        return
    raise AssertionError("должна быть ошибка")