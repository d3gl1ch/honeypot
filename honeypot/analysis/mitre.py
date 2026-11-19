# привязка действий атакующих к mitre att&ck
import re
from collections import Counter

from honeypot.analysis.sessions import load_sessions
from honeypot.events import AUTH, COMMAND, HTTP_REQUEST
from honeypot.storage.db import Storage

# id -> (название, тактика)
TECHNIQUES = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1003.008": ("/etc/passwd and /etc/shadow", "Credential Access"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1053.003": ("Cron", "Persistence"),
    "T1098.004": ("SSH Authorized Keys", "Persistence"),
    "T1222.002": ("File Permissions Modification", "Defense Evasion"),
    "T1070.003": ("Clear Command History", "Defense Evasion"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1033": ("System Owner/User Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1496": ("Resource Hijacking", "Impact"),
}

# правила для команд: регулярка -> техника
CMD_RULES = [
    (r"\buname\b|/etc/os-release|/proc/cpuinfo|\bhostname\b|\blscpu\b", "T1082"),
    (r"\bwhoami\b|\bid\b|\bwho\b", "T1033"),
    (r"\b(ls|find)\b", "T1083"),
    (r"\b(ps|top|htop)\b", "T1057"),
    (r"/etc/(passwd|shadow)", "T1003.008"),
    (r"\b(wget|curl|tftp|ftpget)\b", "T1105"),
    (r"\b(sh|bash)\s+\S+|(^|[;&|]\s*)\./\w", "T1059.004"),
    (r"\b(chmod|chown)\b", "T1222.002"),
    (r"history\s+-c|\.bash_history|unset\s+HISTFILE", "T1070.003"),
    (r"authorized_keys", "T1098.004"),
    (r"\bcrontab\b|/etc/cron", "T1053.003"),
    (r"xmrig|minerd|cpuminer|stratum\+tcp", "T1496"),
]

# типы веб-атак из http сенсора -> техника
HTTP_ATTACKS = {
    "sqli": "T1190",
    "xss": "T1190",
    "traversal": "T1190",
    "rce": "T1190",
    "scanner": "T1595",
}


def map_command(cmd):
    return {tech for rx, tech in CMD_RULES if re.search(rx, cmd)}


def map_event(e):
    p = e["payload"]
    found = set()
    if e["event_type"] == AUTH:
        found.add("T1110")
        if p.get("success"):  # пустили внутрь
            found.add("T1078")
    elif e["event_type"] == COMMAND:
        found |= map_command(p.get("cmd", ""))
    elif e["event_type"] == HTTP_REQUEST:
        for a in p.get("attacks", []):
            found.add(HTTP_ATTACKS[a])
        if p.get("password"):  # пробовали войти через форму
            found.add("T1110")
    return found


def summarize(storage):
    # считаем в скольких сессиях встретилась каждая техника
    techs = Counter()
    for events in load_sessions(storage).values():
        found = set()
        for e in events:
            found |= map_event(e)
        techs.update(found)

    tactics = Counter()
    for tid, n in techs.items():
        tactics[TECHNIQUES[tid][1]] += n
    return techs, tactics


if __name__ == "__main__":
    db = Storage("logs/fake.db")
    techs, tactics = summarize(db)
    for tid, n in techs.most_common():
        name, tactic = TECHNIQUES[tid]
        print(f"{tid:10} {name} ({tactic}): {n}")
    print()
    print("по тактикам:", dict(tactics))