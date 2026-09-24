"""Bounded workspace actions executed inside an ephemeral worker boundary."""

import os
import subprocess
from pathlib import Path

from connectd.worker import LocalAuthority, WorkerError


WORKBENCH_TOOL = {
    "type": "function",
    "function": {
        "name": "workbench",
        "description": "Read or write a workspace file, or run a local command in the workspace.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["read", "write", "run"]},
                "path": {"type": "string"},
                "content": {"type": "string"},
                "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    },
}


class LocalWorkbench:
    def __init__(self, root: Path, authority: LocalAuthority):
        self.root = root.resolve(strict=True)
        self.authority = authority

    def _path(self, value: str) -> Path:
        if not value or Path(value).is_absolute():
            raise WorkerError("workspace path must be relative")
        path = (self.root / value).resolve()
        if not path.is_relative_to(self.root):
            raise WorkerError("workspace path escapes the worktree")
        return path

    def __call__(self, _tool_name: str, args: dict) -> dict:
        action = args.get("action")
        if action == "read":
            if not self.authority.read_workspace:
                raise WorkerError("workspace read is unavailable")
            path = self._path(args.get("path", ""))
            if not path.is_file() or path.stat().st_size > 1_000_000:
                raise WorkerError("file missing or too large")
            return {"content": path.read_text(encoding="utf-8")}
        if action == "write":
            if not self.authority.write_workspace:
                raise WorkerError("workspace write is unavailable")
            path = self._path(args.get("path", ""))
            content = args.get("content")
            if not isinstance(content, str) or len(content.encode("utf-8")) > 1_000_000:
                raise WorkerError("invalid file content")
            path.parent.mkdir(parents=True, exist_ok=True)
            # Re-resolve after directory creation to catch newly exposed links.
            self._path(args["path"]).write_text(content, encoding="utf-8")
            return {"written": args["path"]}
        if action == "run":
            if not self.authority.execute_local:
                raise WorkerError("workspace execution is unavailable")
            argv = args.get("argv")
            if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
                raise WorkerError("command must be a nonempty argument list")
            env = {key: value for key, value in os.environ.items()
                   if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
            try:
                result = subprocess.run(argv, cwd=self.root, env=env, capture_output=True,
                                        text=True, timeout=30, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise WorkerError("local command failed to start or timed out") from exc
            return {"exit_code": result.returncode, "stdout": result.stdout[:20_000],
                    "stderr": result.stderr[:20_000]}
        raise WorkerError("unknown workbench action")
