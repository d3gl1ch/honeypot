# пишет события в файл (jsonl) и, если нужно, в базу
from pathlib import Path


class EventLogger:
    def __init__(self, path="logs/events.jsonl", storage=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.storage = storage

    def log(self, event):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(event.to_json() + "\n")
        if self.storage:
            self.storage.save(event)