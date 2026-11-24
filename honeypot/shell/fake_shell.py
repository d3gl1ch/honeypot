# поддельная консоль: виртуальная файловая система и несколько команд
import hashlib
from pathlib import Path
from urllib.parse import urlparse
import hashlib
import re
import shlex
from pathlib import Path
from urllib.parse import urlparse

# папки: путь -> что внутри
DIRS = {
    "/": ["bin", "etc", "home", "root", "tmp", "var"],
    "/bin": [],
    "/etc": ["passwd", "hostname", "os-release"],
    "/home": ["user"],
    "/home/user": [".bash_history", "notes.txt"],
    "/root": [],
    "/tmp": [],
    "/var": [],
}

# файлы: путь -> содержимое
FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n",
    "/etc/hostname": "srv01\n",
    "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n',
    "/home/user/notes.txt": "todo: update server\n",
}

SEPARATORS = re.compile(r"\s*(?:;|&&|\|\|)\s*")
PIPE = re.compile(r"\s*\|\s*")


class FakeShell:
    def __init__(self, user="root", host="srv01"):
        self.user = user
        self.host = host
        self.home = "/root" if user == "root" else "/home/user"
        self.cwd = self.home
        self.closed = False  # станет True после exit
        self.downloads = []  # "скачанные" атакующим файлы (для DOWNLOAD)
        self.history = []  # история команд для history

    def prompt(self):
        sign = "#" if self.user == "root" else "$"
        return f"{self.user}@{self.host}:{self.cwd}{sign} "

    def _abs(self, path):
        # делаем абсолютный путь, убираем . и ..
        if not path.startswith("/"):
            path = self.cwd + "/" + path
        parts = []
        for p in path.split("/"):
            if p == "" or p == ".":
                continue
            if p == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(p)
        return "/" + "/".join(parts)

    def run(self, line):
        # выполняет цепочку команд, разделённых ; && || и |
        results = []
        for chunk in SEPARATORS.split(line):
            if chunk.strip():
                results.append(self._run_pipe(chunk))
            if self.closed:
                break
        return "".join(results)

    def _run_pipe(self, chunk):
        data = ""
        for stage in PIPE.split(chunk):
            data = self._run_cmd(stage, data)
        return data

    def _run_cmd(self, segment, stdin=""):
        try:
            parts = shlex.split(segment)
        except ValueError:
            return "bash: syntax error near unexpected token\n"
        if not parts:
            return ""
        cmd, args = parts[0], parts[1:]
        if cmd != "history":
            self.history.append(" ".join(parts))
        func = getattr(self, "cmd_" + cmd, None)
        if func is None:
            return f"bash: {cmd}: command not found\n"
        if cmd in ("cat", "grep", "wc", "head", "tail"):
            return func(args, stdin)
        return func(args)

    def cmd_pwd(self, args):
        return self.cwd + "\n"

    def cmd_cd(self, args):
        target = self._abs(args[0]) if args else self.home
        if target in DIRS:
            self.cwd = target
            return ""
        if target in FILES:
            return f"bash: cd: {args[0]}: Not a directory\n"
        return f"bash: cd: {args[0]}: No such file or directory\n"

    def cmd_ls(self, args):
        flags = [a for a in args if a.startswith("-")]
        paths = [a for a in args if not a.startswith("-")]
        target = self._abs(paths[0]) if paths else self.cwd

        if target in FILES:
            return paths[0] + "\n"
        if target not in DIRS:
            return f"ls: cannot access '{paths[0]}': No such file or directory\n"

        names = DIRS[target]
        if not any("a" in f for f in flags):
            names = [n for n in names if not n.startswith(".")]  # скрытые только с -a
        if not names:
            return ""
        return "  ".join(sorted(names)) + "\n"

    def cmd_cat(self, args, stdin=""):
        if not args:
            return stdin
        out = ""
        for a in args:
            path = self._abs(a)
            if path in FILES:
                out += FILES[path]
            elif path in DIRS:
                out += f"cat: {a}: Is a directory\n"
            else:
                out += f"cat: {a}: No such file or directory\n"
        return out

    def cmd_whoami(self, args):
        return self.user + "\n"

    def cmd_id(self, args):
        if self.user == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        return f"uid=1000({self.user}) gid=1000({self.user}) groups=1000({self.user})\n"

    def cmd_uname(self, args):
        if "-a" in args:
            return "Linux srv01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"
        return "Linux\n"

    def cmd_echo(self, args):
        return " ".join(args) + "\n"

    def _fake_download(self, url, target=None):
        # наружу не ходим: детерминированная заглушка, хэш считаем реально
        url = url.strip("\"'")
        name = target or Path(urlparse(url).path).name or "payload.bin"
        name = Path(name).name  # вырезаем ../ из имени
        content = ("# honeypot fake payload\n"
                   f"# source: {url}\n").encode("utf-8")
        digest = hashlib.sha256(content).hexdigest()
        self.downloads.append({"url": url, "name": name, "sha256": digest,
                               "content": content.decode("utf-8")})
        return (f"--{url}--\n"
                f"Saving to: '{name}'\n\n"
                f"{name} saved [{len(content)}/{len(content)}]\n")

    def cmd_wget(self, args):
        target = url = None
        i = 0
        while i < len(args):
            if args[i] in ("-O", "-o") and i + 1 < len(args):
                target = args[i + 1]
                i += 2
            elif args[i].startswith("-"):
                i += 1
            else:
                url = args[i]
                i += 1
        if not url:
            return "wget: missing URL\n"
        return self._fake_download(url, target)

    def cmd_curl(self, args):
        target = url = None
        i = 0
        while i < len(args):
            if args[i] in ("-o", "--output") and i + 1 < len(args):
                target = args[i + 1]
                i += 2
            elif args[i].startswith("-"):
                i += 1
            else:
                url = args[i]
                i += 1
        if not url:
            return "curl: missing URL\n"
        return self._fake_download(url, target)


    def cmd_chmod(self, args):
        if not args:
            return "chmod: missing operand\n"
        return ""  # для root просто "меняем" права

    def cmd_ps(self, args):
        if any(a in ("aux", "ef", "-ef") for a in args):
            return ("USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                    "root         1  0.0  0.1  22500  9200 ?        Ss   10:00   0:02 /sbin/init\n"
                    "root       402  0.0  0.1  15500  7100 ?        Ss   10:00   0:00 /usr/sbin/sshd\n"
                    "root       415  0.0  0.0   8500  3100 ?        Ss   10:00   0:00 /usr/sbin/cron\n")
        return ("  PID TTY          TIME CMD\n"
                "    1 ?        00:00:02 systemd\n"
                "  402 ?        00:00:00 sshd\n"
                "  415 ?        00:00:00 cron\n")

    def cmd_history(self, args):
        if "-c" in args:
            self.history.clear()
            return ""
        return "".join(f"{i:5}  {c}\n" for i, c in enumerate(self.history, 1))

    def cmd_grep(self, args, stdin=""):
        flags = [a for a in args if a.startswith("-")]
        pattern = next((a for a in args if not a.startswith("-")), "")
        if not pattern:
            return "usage: grep [OPTION]... PATTERN [FILE]...\n"
        lines = stdin.splitlines()
        if "-v" in flags:
            lines = [l for l in lines if pattern not in l]
        elif "-i" in flags:
            lines = [l for l in lines if pattern.lower() in l.lower()]
        else:
            lines = [l for l in lines if pattern in l]
        return "".join(l + "\n" for l in lines)

    def cmd_wc(self, args, stdin=""):
        lines = stdin.splitlines()
        if "-l" in args:
            return f"{len(lines)}\n"
        return f"{len(lines)} {len(stdin.split())} {len(stdin)}\n"

    def cmd_head(self, args, stdin=""):
        n = self._count_arg(args)
        return "".join(l + "\n" for l in stdin.splitlines()[:n])

    def cmd_tail(self, args, stdin=""):
        n = self._count_arg(args)
        lines = stdin.splitlines()
        return "".join(l + "\n" for l in lines[-n:]) if n else ""

    def _count_arg(self, args):
        for i, a in enumerate(args):
            if a == "-n" and i + 1 < len(args) and args[i + 1].isdigit():
                return int(args[i + 1])
            if a.isdigit():
                return int(a)
        return 10

    def cmd_exit(self, args):
        self.closed = True
        return "logout\n"

    cmd_logout = cmd_exit


if __name__ == "__main__":
    # можно поиграться руками
    sh = FakeShell()
    while not sh.closed:
        print(sh.run(input(sh.prompt())), end="")