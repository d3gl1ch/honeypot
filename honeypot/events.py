# общий формат события, его используют обе части проекта
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json
import uuid

# типы событий
CONNECT = "connect"
AUTH = "auth"
COMMAND = "command"
DOWNLOAD = "download"
HTTP_REQUEST = "http_request"
DISCONNECT = "disconnect"


def now_iso():
    # время всегда в utc
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Event:
    service: str       # ssh / http / telnet
    event_type: str    # одна из констант выше
    src_ip: str
    src_port: int = 0
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    ts: str = field(default_factory=now_iso)
    payload: dict = field(default_factory=dict)  # всё остальное (логин, команда и т.д.)

    def to_json(self):
        return json.dumps(asdict(self), ensure_ascii=False)