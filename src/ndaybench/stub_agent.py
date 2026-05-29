"""Deterministic stub agent — exercises every tool, then submits a wrong flag.

Used to validate the runner + tool plumbing + DB without burning real LLM
inference.  Logs a turn-by-turn transcript to `transcript.jsonl` mirroring the
shape a real ReAct/tool-use agent will write.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from .tools import TOOLS, RunContext
from .vm import utcnow_iso


def _say(ctx: RunContext, turn: int, kind: str, content: Any) -> None:
    record = {"ts": utcnow_iso(), "turn": turn, "role": "agent", "kind": kind, "content": content}
    with (ctx.run_dir / "transcript.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def _call(ctx: RunContext, turn: int, tool: str, **kwargs: Any) -> dict[str, Any]:
    fn = TOOLS[tool]
    _say(ctx, turn, "tool_call", {"tool": tool, "kwargs": kwargs})
    result = fn(ctx, **kwargs)
    _say(ctx, turn, "tool_result", {"tool": tool, "result": result})
    return result


def run(ctx: RunContext, vm_role: str = "sole") -> None:
    """Drive the stub through every tool in a deterministic order."""

    _say(ctx, 0, "thought", "stub agent: exercising the tool surface")

    # 1. ssh_exec — confirm low-priv user
    _call(ctx, 1, "ssh_exec", cmd="whoami", vm=vm_role)

    # 2. ssh_exec — confirm flag is NOT directly readable
    _call(ctx, 2, "ssh_exec",
          cmd=r"type C:\Users\Administrator\Desktop\root.txt",
          vm=vm_role, timeout=20)

    # 3. push_file — drop a known blob in agent's profile
    payload = b"ndaybench-stub-payload\n"
    _call(ctx, 3, "push_file",
          remote_path=r"C:\Users\agent\Desktop\stub.txt",
          content_b64=base64.b64encode(payload).decode(),
          vm=vm_role)

    # 4. pull_file — read it back
    pulled = _call(ctx, 4, "pull_file",
                   remote_path=r"C:\Users\agent\Desktop\stub.txt",
                   vm=vm_role)
    _say(ctx, 4, "thought",
         {"roundtrip_ok": base64.b64decode(pulled.get("content_b64", "")) == payload})

    # 5. vm_reboot — power cycle, confirm tool can recover SSH after boot
    _call(ctx, 5, "vm_reboot", vm=vm_role)

    # 6. ssh_exec post-reboot — confirm the pushed file survived
    _call(ctx, 6, "ssh_exec",
          cmd=r"type C:\Users\agent\Desktop\stub.txt", vm=vm_role)

    # 7. vm_revert — roll back to pre-stub snapshot
    _call(ctx, 7, "vm_revert", vm=vm_role)

    # 8. ssh_exec post-revert — confirm the pushed file is GONE
    _call(ctx, 8, "ssh_exec",
          cmd=r"if exist C:\Users\agent\Desktop\stub.txt (echo PRESENT) else (echo GONE)",
          vm=vm_role)

    # 9. submit a wrong flag — exercises the oracle's failure path
    _call(ctx, 9, "submit", flag="ndaybench{stub_does_not_actually_exploit}")

    _say(ctx, 10, "thought", "stub agent: done")
