from __future__ import annotations
import json
import pathlib
from datetime import datetime, timezone
from typing import Any


class Memory:
    def __init__(self, case_id: str = "DEFAULT-CASE", artifacts_root: str | pathlib.Path = "artifacts"):
        self.case_id = case_id
        self.artifacts_dir = pathlib.Path(artifacts_root) / case_id
        self.raw_dir = self.artifacts_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.messages: list[dict[str, Any]] = []

    def add(
        self,
        role: str,
        content: str | None = None,
        tool_calls: Any = None,
        tool_call_id: str | None = None,
        name: str | None = None,
    ) -> None:
        msg: dict[str, Any] = {"role": role, "content": content or ""}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        if tool_call_id:
            msg["tool_call_id"] = tool_call_id
        if name:
            msg["name"] = name
        self.messages.append(msg)

    def recent_summary(self, last_n: int = 4) -> str:
        recent = self.messages[-last_n:]
        parts = []
        for m in recent:
            role = m.get("role", "")
            name = m.get("name", "")
            content = str(m.get("content", ""))[:300]
            parts.append(f"[{role}{':' + name if name else ''}] {content}")
        return "\n".join(parts)

    def save_artifact(self, filename: str, data: Any, raw: bool = True) -> pathlib.Path:
        target_dir = self.raw_dir if raw else self.artifacts_dir
        path = target_dir / filename
        if isinstance(data, (dict, list)):
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            path.write_text(str(data), encoding="utf-8")
        return path

    def snapshot(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "messages": self.messages,
            "artifacts_dir": str(self.artifacts_dir),
        }

    def restore(self, state: dict[str, Any]) -> None:
        self.case_id = state.get("case_id", self.case_id)
        self.messages = list(state.get("messages", []))
        if "artifacts_dir" in state:
            self.artifacts_dir = pathlib.Path(state["artifacts_dir"])
            self.raw_dir = self.artifacts_dir / "raw"
            self.raw_dir.mkdir(parents=True, exist_ok=True)
