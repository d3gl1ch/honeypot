from honeypot.shell.fake_shell import FakeShell


def test_pwd_and_cd():
    sh = FakeShell("root")
    assert sh.run("pwd") == "/root\n"
    sh.run("cd /etc")
    assert sh.run("pwd") == "/etc\n"
    sh.run("cd ..")
    assert sh.cwd == "/"


def test_ls_and_cat():
    sh = FakeShell()
    assert "passwd" in sh.run("ls /etc")
    assert sh.run("cat /etc/hostname") == "srv01\n"
    assert ".bash_history" not in sh.run("ls /home/user")
    assert ".bash_history" in sh.run("ls -a /home/user")


def test_errors():
    sh = FakeShell()
    assert "command not found" in sh.run("hack")
    assert "No such file" in sh.run("cat /nope")
    assert "No such file" in sh.run("cd /nope")


def test_exit():
    sh = FakeShell()
    sh.run("exit")
    assert sh.closed