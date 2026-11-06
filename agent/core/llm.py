from __future__ import annotations
import json
import os
from dataclasses import dataclass
from typing import Any
import requests


@dataclass
class FunctionCall:
    name: str
    arguments: str


@dataclass
class ToolCall:
    id: str
    function: FunctionCall
    type: str = "function"


@dataclass
class Message:
    content: str | None
    tool_calls: list[ToolCall] | None = None
    role: str = "assistant"


@dataclass
class Choice:
    message: Message


@dataclass
class ChatResponse:
    choices: list[Choice]


MODEL_MAP = {
    "deepseek-v4.1-flash": "deepseek-chat",
    "deepseek-v4-pro": "deepseek-reasoner",
}


class DeepSeekLLM:
    """OpenAI-compatible wrapper for DeepSeek API with deterministic dry-run fallback."""

    def __init__(self, base_url: str = "https://api.deepseek.com/v1", api_key: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str = "deepseek-v4.1-flash",
        temperature: float = 0.2,
    ) -> ChatResponse:
        if not self.api_key:
            return self._offline_plan(messages, tools)

        resolved_model = MODEL_MAP.get(model, model)
        payload: dict[str, Any] = {
            "model": resolved_model,
            "messages": messages,
            "temperature": temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        resp = requests.post(
            f"{self.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=90,
        )
        resp.raise_for_status()
        data = resp.json()
        raw_msg = data["choices"][0]["message"]
        tcs = None
        if raw_msg.get("tool_calls"):
            tcs = [
                ToolCall(
                    id=tc["id"],
                    function=FunctionCall(
                        name=tc["function"]["name"],
                        arguments=tc["function"]["arguments"],
                    ),
                )
                for tc in raw_msg["tool_calls"]
            ]
        return ChatResponse(choices=[Choice(message=Message(content=raw_msg.get("content"), tool_calls=tcs))])

    def _offline_plan(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None
    ) -> ChatResponse:
        """Deterministic multi-step execution when DEEPSEEK_API_KEY is not set (dry-run mode)."""
        executed_tools = {m.get("name") for m in messages if m.get("role") == "tool"}
        available = {t["function"]["name"] for t in (tools or [])}
        user_task = next((m["content"] for m in messages if m["role"] == "user"), "")

        import re
        phone_match = re.search(r"(\+?\d[\d\s-]{7,14}\d)", user_task)
        phone_val = re.sub(r"[\s-]", "", phone_match.group(1)) if phone_match else "+66942638165"

        pipeline = [
            ("phone-email-osint", {"target": phone_val, "target_type": "phone", "passive_only": True}),
            ("syndicate-roster-tracker", {"channel": "@bv92111", "target_alias": "予安 / 小白"}),
            ("digital-forensics-investigator", {"target": phone_val, "correlate_roaming": True}),
            ("case-dossier-exporter", {"case_id": "2026-11-05-CASE-001", "languages": ["th", "zh-TW"]}),
        ]

        for idx, (skill_name, sample_args) in enumerate(pipeline, start=1):
            if skill_name in available and skill_name not in executed_tools:
                return ChatResponse(
                    choices=[
                        Choice(
                            message=Message(
                                content=f"[Step {idx}] Calling `{skill_name}`...",
                                tool_calls=[
                                    ToolCall(
                                        id=f"call_{idx}_{skill_name}",
                                        function=FunctionCall(
                                            name=skill_name,
                                            arguments=json.dumps(sample_args, ensure_ascii=False),
                                        ),
                                    )
                                ],
                            )
                        )
                    ]
                )

        summary_lines = ["✅ ดำเนินการสืบสวนตาม Pipeline และบันทึก Artifacts ครบถ้วนแล้ว:"]
        for m in messages:
            if m.get("role") == "tool":
                summary_lines.append(f"- **{m.get('name')}**: `{m.get('content')[:160]}...`")
        return ChatResponse(choices=[Choice(message=Message(content="\n".join(summary_lines), tool_calls=None))])
