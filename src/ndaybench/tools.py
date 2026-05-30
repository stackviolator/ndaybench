"""Agent-facing tools for ndaybench runs (OpenVMM backend).

Each tool takes a `RunContext` (which holds the VMs, ground-truth flag, run dir)
and tool-specific kwargs, logs the call+result to `tool_calls.jsonl`, and returns
a serializable dict.

Guest access goes through `OpenVmmClient` over SSH.  Tools run as the low-priv
*agent* account (the LPE target user); the harness setup elsewhere runs as the
admin account.  For v0 the tool surface is single-VM only (the `vm` keyword is
plumbed but defaults to "sole").
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .openvmm import OpenVmmClient, OpenVmmVm, utcnow_iso
from .oracle import grade


@dataclass
class VmContext:
    role: str           # "sole" | "scoring" | "scratch"
    vm: OpenVmmVm
    client: OpenVmmClient
    agent_user: str = "victim"
    agent_password: str = ""

    def exec(self, cmd: str, *, timeout: int = 60) -> dict[str, Any]:
        """Run `cmd` in the guest as the agent (low-priv) user."""
        return self.client.guest_exec(
            self.vm, cmd, timeout=timeout, check=False,
            user=self.agent_user, password=self.agent_password,
        )

    def powershell(self, script: str, *, timeout: int = 60) -> dict[str, Any]:
        return self.client.guest_powershell(
            self.vm, script, timeout=timeout, check=False,
            user=self.agent_user, password=self.agent_password,
        )

    @property
    def snapshot_name(self) -> str | None:
        return self.vm.snapshot_name


class BudgetExceeded(RuntimeError):
    """Raised when the run exceeds its wall-clock budget."""


@dataclass
class RunContext:
    run_id: str
    run_dir: Path
    client: OpenVmmClient
    expected_flag: str
    vms: dict[str, VmContext]
    deadline_monotonic: float | None = field(default=None)
    submission: str | None = field(default=None)
    submission_correct: bool | None = field(default=None)

    def log(self, tool: str, args: dict[str, Any], result: dict[str, Any]) -> None:
        record = {"ts": utcnow_iso(), "tool": tool, "args": args, "result": result}
        with (self.run_dir / "tool_calls.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

    def check_budget(self) -> None:
        """Raise BudgetExceeded if the wall-clock deadline has passed."""
        if self.deadline_monotonic is None:
            return
        import time as _time
        if _time.monotonic() > self.deadline_monotonic:
            raise BudgetExceeded(f"wall-clock budget exceeded for run {self.run_id}")


# --- tool implementations ---------------------------------------------------


def _redact(s: str, max_len: int = 4000) -> str:
    return s if len(s) <= max_len else s[:max_len] + f"...[+{len(s)-max_len} bytes]"


def ssh_exec(ctx: RunContext, *, cmd: str, vm: str = "sole", timeout: int = 60) -> dict[str, Any]:
    """Run `cmd` on the guest VM as the agent user (default Windows shell: cmd.exe)."""
    ctx.check_budget()
    result = ctx.vms[vm].exec(cmd, timeout=timeout)
    out = {
        "stdout": _redact(str(result["stdout"])),
        "stderr": _redact(str(result["stderr"])),
        "exit_code": result["exit_code"],
    }
    ctx.log("ssh_exec", {"vm": vm, "cmd": cmd, "timeout": timeout}, out)
    return out


def push_file(
    ctx: RunContext, *, remote_path: str, content_b64: str, vm: str = "sole"
) -> dict[str, Any]:
    """Write the base64-decoded bytes to `remote_path` on the guest VM."""
    ctx.check_budget()
    ps = (
        f"$d=[Convert]::FromBase64String('{content_b64}'); "
        f"$p='{remote_path}'; "
        f"$dir=Split-Path $p -Parent; "
        f"if ($dir -and -not (Test-Path $dir)) "
        f"{{ New-Item -ItemType Directory -Path $dir -Force | Out-Null }}; "
        f"[IO.File]::WriteAllBytes($p, $d); "
        f"Write-Host \"wrote $($d.Length) bytes to $p\""
    )
    result = ctx.vms[vm].powershell(ps, timeout=60)
    out = {
        "stdout": _redact(str(result["stdout"])),
        "stderr": _redact(str(result["stderr"])),
        "exit_code": result["exit_code"],
        "bytes_written": len(base64.b64decode(content_b64)),
    }
    ctx.log(
        "push_file",
        {"vm": vm, "remote_path": remote_path, "content_b64_len": len(content_b64)},
        out,
    )
    return out


def pull_file(ctx: RunContext, *, remote_path: str, vm: str = "sole") -> dict[str, Any]:
    """Read `remote_path` on the guest VM and return it base64-encoded."""
    ctx.check_budget()
    ps = (
        f"$b=[IO.File]::ReadAllBytes('{remote_path}'); "
        f"[Convert]::ToBase64String($b)"
    )
    result = ctx.vms[vm].powershell(ps, timeout=60)
    out: dict[str, Any] = {
        "stderr": _redact(str(result["stderr"])),
        "exit_code": result["exit_code"],
    }
    if result["exit_code"] == 0:
        content_b64 = str(result["stdout"]).strip()
        out["content_b64"] = content_b64
        try:
            out["bytes_read"] = len(base64.b64decode(content_b64))
        except Exception as exc:  # noqa: BLE001
            out["decode_error"] = str(exc)
    else:
        out["stdout"] = _redact(str(result["stdout"]))
    ctx.log("pull_file", {"vm": vm, "remote_path": remote_path}, out)
    return out


def vm_reboot(ctx: RunContext, *, vm: str = "sole") -> dict[str, Any]:
    ctx.check_budget()
    vmctx = ctx.vms[vm]
    ctx.client.reboot(vmctx.vm)
    out = {"ip": vmctx.vm.ip, "status": "ready"}
    ctx.log("vm_reboot", {"vm": vm}, out)
    return out


def vm_revert(ctx: RunContext, *, vm: str = "sole") -> dict[str, Any]:
    """Roll the VM back to its pre-agent snapshot."""
    ctx.check_budget()
    vmctx = ctx.vms[vm]
    if not vmctx.snapshot_name:
        out = {"error": "no snapshot taken for this VM"}
        ctx.log("vm_revert", {"vm": vm}, out)
        return out
    ctx.client.restore(vmctx.vm, vmctx.snapshot_name)
    out = {"ip": vmctx.vm.ip, "snapshot": vmctx.snapshot_name, "status": "reverted"}
    ctx.log("vm_revert", {"vm": vm}, out)
    return out


def submit(ctx: RunContext, *, flag: str) -> dict[str, Any]:
    """Submit a candidate flag to the oracle.  Ends the episode."""
    result = grade(ctx.expected_flag, flag)
    ctx.submission = flag
    ctx.submission_correct = bool(result["pass_"])
    out = {"pass": result["pass_"], "evidence": result["evidence"]}
    ctx.log("submit", {"flag_len": len(flag)}, out)
    return out


TOOLS = {
    "ssh_exec": ssh_exec,
    "push_file": push_file,
    "pull_file": pull_file,
    "vm_reboot": vm_reboot,
    "vm_revert": vm_revert,
    "submit": submit,
}
