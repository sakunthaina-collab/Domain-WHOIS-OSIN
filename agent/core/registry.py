from __future__ import annotations
import pathlib
from dataclasses import dataclass, field
from typing import Any
import yaml


@dataclass
class Skill:
    name: str
    description: str
    category: str
    input_schema: dict[str, Any]
    runtime: dict[str, Any]
    version: str = "1.0.0"
    status: str = "runnable"  # runnable | stub | deprecated
    triggers: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    risk: str = "low"
    outputs: list[str] = field(default_factory=list)
    dir: pathlib.Path | None = None

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


@dataclass
class Profile:
    name: str
    model: str
    categories: list[str]
    top_k: int = 12
    temperature: float = 0.2
    escalate_model: str | None = None
    seed: int = 42
    system_prompt: str = "You are a helpful AI agent."
    guardrails: dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        setattr(self, key, value)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    @classmethod
    def from_yaml(cls, path: str | pathlib.Path) -> "Profile":
        data = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8"))
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class Registry:
    def __init__(self, root: str | pathlib.Path = "skills", include_stubs: bool = False):
        self.root = pathlib.Path(root)
        self.include_stubs = include_stubs
        self.skills: dict[str, Skill] = {}
        self.all_loaded: list[Skill] = []
        if self.root.exists():
            for p in sorted(self.root.rglob("skill.yaml")):
                d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                valid_keys = {k: v for k, v in d.items() if k in Skill.__dataclass_fields__}
                s = Skill(**valid_keys)
                s.dir = p.parent
                self.all_loaded.append(s)
                is_stub = s.status == "stub" or "_stubs" in p.parts
                if not include_stubs and is_stub:
                    continue
                existing = self.skills.get(s.name)
                if existing is None or (existing.status == "stub" and s.status == "runnable"):
                    self.skills[s.name] = s

    def get(self, name: str) -> Skill | None:
        return self.skills.get(name)

    def subset(self, categories: list[str] | None = None) -> list[Skill]:
        if not categories:
            return list(self.skills.values())
        return [s for s in self.skills.values() if s.category in categories]

    def to_openai_tools(self, names: list[str]) -> list[dict[str, Any]]:
        tools = []
        for n in names:
            if n in self.skills:
                s = self.skills[n]
                tools.append({
                    "type": "function",
                    "function": {
                        "name": s.name,
                        "description": s.description.strip(),
                        "parameters": s.input_schema,
                    },
                })
        return tools
