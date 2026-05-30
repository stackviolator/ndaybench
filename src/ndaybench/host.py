"""Typed SSH transport to the OpenVMM host.

Every shell-out in the OpenVMM backend goes through a single ``Host`` object so
the SSH plumbing lives in one tested place instead of scattered f-strings.  The
runtime *and* the bakery share it.  ``CmdResult`` replaces the ad-hoc
``CompletedProcess``/dict returns with a typed value.

The shell itself (``ip``, ``mount``, ``systemctl``, ``wusa``, ...) is
irreducible — these are shell tools — but how we invoke it is now typed,
centralized, and unit-testable (subclass/replace ``Host`` with a fake that
records commands instead of running them).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field


class HostError(RuntimeError):
    """A host command failed (non-zero exit when ``check=True``)."""


@dataclass(frozen=True)
class CmdResult:
    """Result of a command run on the host."""

    command: str
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def lines(self) -> list[str]:
        return [ln for ln in self.stdout.splitlines() if ln.strip()]


@dataclass(frozen=True)
class Host:
    """SSH transport to a single host. All OpenVMM shell-out flows through here."""

    name: str = "p620-1"
    user: str = "root"
    ssh_opts: tuple[str, ...] = field(
        default=(
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
        )
    )

    @property
    def target(self) -> str:
        return f"{self.user}@{self.name}"

    def ssh_argv(self, *extra: str) -> list[str]:
        """Base ssh argv (``ssh <opts> user@host`` + any extra args)."""
        return ["ssh", *self.ssh_opts, *extra, self.target]

    def run(self, command: str, *, timeout: int = 60, check: bool = True) -> CmdResult:
        """Run a single remote command string over SSH."""
        proc = subprocess.run(
            [*self.ssh_argv(), command],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        res = CmdResult(command, proc.returncode, proc.stdout, proc.stderr)
        if check and not res.ok:
            raise HostError(
                f"host cmd failed (rc={res.returncode}): {command!r}\n"
                f"stdout: {res.stdout}\nstderr: {res.stderr}"
            )
        return res

    def script(self, script: str, *, timeout: int = 120, check: bool = True) -> CmdResult:
        """Run a bash script on the host via ``bash -s`` (avoids quoting hell)."""
        proc = subprocess.run(
            [*self.ssh_argv(), "bash", "-s"],
            input=script, capture_output=True, text=True, timeout=timeout, check=False,
        )
        res = CmdResult("bash -s", proc.returncode, proc.stdout, proc.stderr)
        if check and not res.ok:
            raise HostError(
                f"host script failed (rc={res.returncode})\n"
                f"stdout: {res.stdout}\nstderr: {res.stderr}"
            )
        return res

    def forward(self, local_port: int, remote_hostport: str) -> subprocess.Popen:
        """Start a backgrounded ``ssh -L`` TCP forward; caller owns the Popen."""
        return subprocess.Popen(
            self.ssh_argv("-N", "-T", "-L", f"127.0.0.1:{local_port}:{remote_hostport}")
        )
