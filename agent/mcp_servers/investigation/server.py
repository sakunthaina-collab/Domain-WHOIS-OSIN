"""
MCP Server (stdio JSON-RPC 2.0) exposing the 5 Investigation Skills to Antigravity / MCP Clients
with built-in Guardrails and Chain-of-Custody Audit Logging.
"""
from __future__ import annotations
import json
import pathlib
import sys
import time
from typing import Any

AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from core.executor import Executor
from core.guardrails import Guardrails
from core.registry import Profile, Registry


class InvestigationMCPServer:
    def __init__(self):
        self.reg = Registry(AGENT_DIR / "skills")
        self.profile = Profile.from_yaml(AGENT_DIR / "profiles" / "investigator.yaml")
        self.exec = Executor(sandbox=AGENT_DIR / "sandbox")
        self.guard = Guardrails(log_path=AGENT_DIR / "logs" / "audit.jsonl")
        self.step_counter = 0

    def list_tools(self) -> list[dict[str, Any]]:
        inv_skills = self.reg.subset(["investigation"])
        return [
            {
                "name": s.name,
                "description": s.description.strip(),
                "inputSchema": s.input_schema,
            }
            for s in inv_skills
        ]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        skill = self.reg.get(name)
        if skill is None:
            return {"isError": True, "content": [{"type": "text", "text": f"Unknown tool: {name}"}]}

        self.step_counter += 1
        t0 = time.perf_counter()
        if not self.guard.allow(skill, arguments, self.profile):
            err = {"ok": False, "error": f"blocked by guardrail: {self.guard.last_reason}"}
            self.guard.audit(
                skill,
                arguments,
                step=self.step_counter,
                case_id=arguments.get("case_id", "MCP-SESSION"),
                result=err,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
                status="blocked",
            )
            return {"isError": True, "content": [{"type": "text", "text": json.dumps(err, ensure_ascii=False)}]}

        res = self.exec.run(skill, arguments)
        self.guard.audit(
            skill,
            arguments,
            step=self.step_counter,
            case_id=arguments.get("case_id", "MCP-SESSION"),
            result=res,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            status="ok" if res.get("ok", True) else "error",
        )
        return {
            "isError": not res.get("ok", True),
            "content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False, indent=2)}],
        }

    def handle_request(self, req: dict[str, Any]) -> dict[str, Any] | None:
        method = req.get("method", "")
        req_id = req.get("id")
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "investigation-mcp-server", "version": "1.0.0"},
                },
            }
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": self.list_tools()}}
        if method == "tools/call":
            params = req.get("params", {})
            res = self.call_tool(params.get("name", ""), params.get("arguments", {}) or {})
            return {"jsonrpc": "2.0", "id": req_id, "result": res}
        if req_id is not None:
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}
        return None

    def serve_stdio(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            req = json.loads(line)
            resp = self.handle_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    InvestigationMCPServer().serve_stdio()
