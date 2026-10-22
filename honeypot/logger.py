# пишет события в файл, одна строка = одно событие (jsonl)
from pathlib import Path


class EventLogger:
    def __init__(self, path="logs/events.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(event.to_json() + "\n")