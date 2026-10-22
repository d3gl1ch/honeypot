# поддельная консоль: виртуальная файловая система и несколько команд

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


class FakeShell:
    def __init__(self, user="root", host="srv01"):
        self.user = user
        self.host = host
        self.home = "/root" if user == "root" else "/home/user"
        self.cwd = self.home
        self.closed = False  # станет True после exit

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
        # выполняет одну команду, возвращает текст ответа
        parts = line.split()
        if not parts:
            return ""
        cmd, args = parts[0], parts[1:]
        func = getattr(self, "cmd_" + cmd, None)
        if func is None:
            return f"bash: {cmd}: command not found\n"
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

    def cmd_cat(self, args):
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

    def cmd_exit(self, args):
        self.closed = True
        return "logout\n"

    cmd_logout = cmd_exit


if __name__ == "__main__":
    # можно поиграться руками
    sh = FakeShell()
    while not sh.closed:
        print(sh.run(input(sh.prompt())), end="")