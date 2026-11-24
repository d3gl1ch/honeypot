# настройки проекта: читаем configs/settings.json и дополняем значениями по умолчанию
import copy
import json
from pathlib import Path

DEFAULTS = {
    "host": "0.0.0.0",
    "ports": {"ssh": 2222, "http": 8080, "telnet": 2323},
    "paths": {
        "ssh_key": "keys/ssh_host_key",
        "db": "logs/events.db",
        "log": "logs/events.jsonl",
        "quarantine": "quarantine",
    },
    "ssh": {
        "weak_passwords": ["123456", "admin", "password", "root", "1234", "qwerty"],
        "max_connections": 100,
        "max_auth_tries": 5,
        "idle_timeout": 60,
        "login_timeout": 30,
        "server_version": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
    },
    "telnet": {
        "weak_passwords": ["123456", "admin", "password", "root", "1234", "qwerty"],
        "idle_timeout": 60,
    },
}


def merge(base, extra):
    # глубоко сливаем словари, значения из extra важнее
    result = dict(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path="configs/settings.json"):
    # если файла нет, работаем на значениях по умолчанию
    p = Path(path)
    data = {}
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise ValueError(f"ошибка в {path}: {e}") from e
    return merge(copy.deepcopy(DEFAULTS), data)