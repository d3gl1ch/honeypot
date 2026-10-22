# хранилище событий в sqlite
import json
import sqlite3
from pathlib import Path


class Storage:
    def __init__(self, path="logs/events.db"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._create_table()

    def _create_table(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                service TEXT,
                event_type TEXT,
                src_ip TEXT,
                src_port INTEGER,
                session_id TEXT,
                payload TEXT
            )
        """)
        # индексы, чтобы анализ работал быстрее
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON events(src_ip)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_session ON events(session_id)")
        self.conn.commit()

    def save(self, ev):
        self.conn.execute(
            "INSERT INTO events (ts, service, event_type, src_ip, src_port, session_id, payload) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ev.ts, ev.service, ev.event_type, ev.src_ip, ev.src_port, ev.session_id,
             json.dumps(ev.payload, ensure_ascii=False)),
        )
        self.conn.commit()

    def get_events(self, service=None, event_type=None, limit=100):
        sql = "SELECT * FROM events WHERE 1=1"
        params = []
        if service:
            sql += " AND service = ?"
            params.append(service)
        if event_type:
            sql += " AND event_type = ?"
            params.append(event_type)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        result = []
        for row in self.conn.execute(sql, params).fetchall():
            d = dict(row)
            d["payload"] = json.loads(d["payload"])  # обратно в словарь
            result.append(d)
        return result

    def count_by(self, column):
        # топ значений по колонке, например по src_ip
        # колонку в запрос подставляем напрямую, поэтому проверяем по списку (защита от sql injection)
        allowed = ("src_ip", "service", "event_type")
        if column not in allowed:
            raise ValueError("нельзя группировать по " + column)
        sql = f"SELECT {column} AS value, COUNT(*) AS cnt FROM events GROUP BY {column} ORDER BY cnt DESC"
        return [dict(r) for r in self.conn.execute(sql).fetchall()]

    def close(self):
        self.conn.close()