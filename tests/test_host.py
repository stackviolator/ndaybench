"""Unit tests for the typed Host transport (no SSH — argv/CmdResult only)."""
from ndaybench.host import CmdResult, Host


def test_cmdresult_ok_and_lines() -> None:
    r = CmdResult("x", 0, "a\n\nb\n", "")
    assert r.ok and r.lines() == ["a", "b"]
    assert not CmdResult("x", 1, "", "boom").ok


def test_host_ssh_argv() -> None:
    h = Host(name="p620-1", user="root", ssh_opts=("-o", "LogLevel=ERROR"))
    assert h.target == "root@p620-1"
    argv = h.ssh_argv("-N", "-L", "1:2")
    assert argv == ["ssh", "-o", "LogLevel=ERROR", "-N", "-L", "1:2", "root@p620-1"]
