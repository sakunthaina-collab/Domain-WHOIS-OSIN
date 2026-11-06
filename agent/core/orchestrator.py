from __future__ import annotations
import json
import pathlib
import time
from typing import Any
from core.artifact_manifest import build_artifact_manifest
from core.case_id_injector import inject_case_id
from core.executor import Executor
from core.guardrails import Guardrails
from core.memory import Memory
from core.registry import Profile, Registry
from core.resilience import ResilientLLM
from core.router import Router


class Orchestrator:
    def __init__(
        self,
        llm: Any,
        registry: Registry,
        router: Router,
        executor: Executor,
        memory: Memory,
        guard: Guardrails,
        profile: Profile | dict[str, Any],
        checkpoint_path: str | pathlib.Path | None = None,
    ):
        self.llm = ResilientLLM(llm, max_retries=3, backoff_delays=(1.0, 2.0, 4.0))
        self.reg = registry
        self.router = router
        self.exec = executor
        self.mem = memory
        self.guard = guard
        self.profile = (
            profile
            if isinstance(profile, Profile)
            else Profile(**{k: v for k, v in profile.items() if k in Profile.__dataclass_fields__})
        )
        self.checkpoint_path = (
            pathlib.Path(checkpoint_path)
            if checkpoint_path
            else self.mem.artifacts_dir / "checkpoint.json"
        )

    def _save_checkpoint(self, step: int, state: dict[str, Any]) -> None:
        if self.checkpoint_path:
            self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            self.checkpoint_path.write_text(
                json.dumps({"step": step, "state": state}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

    def _load_checkpoint(self) -> dict[str, Any] | None:
        if self.checkpoint_path and self.checkpoint_path.exists():
            try:
                return json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None

    def run(
        self,
        task: str,
        max_steps: int = 15,
        escalate: bool = False,
        dry_run: bool = False,
        resume: bool = False,
    ) -> str:
        start_step = 0
        if resume:
            cp = self._load_checkpoint()
            if cp:
                start_step = cp.get("step", 0)
                self.mem.restore(cp.get("state", {}))
                print(f"[*] Resumed checkpoint from step {start_step} for case {self.mem.case_id}")
        else:
            self.mem.add("system", self.profile.system_prompt)
            self.mem.add("user", task)

        tools: list[dict[str, Any]] | None = None
        chosen: list[str] = []

        active_model = (
            self.profile.escalate_model
            if (escalate and self.profile.escalate_model)
            else self.profile.model
        )
        require_confirm = self.profile.guardrails.get("require_confirm", [])
        last_step: int | None = None
        artifact_seq = start_step

        try:
            for step in range(start_step, max_steps):
                if tools is None or step % 3 == 0:
                    chosen = self.router.route(
                        task + "\n" + self.mem.recent_summary(),
                        k=self.profile.top_k,
                        exclude_unconfirmed=require_confirm,
                    )
                    tools = self.reg.to_openai_tools(chosen)

                resp = self.llm.chat(
                    self.mem.messages,
                    tools=tools,
                    model=active_model,
                    temperature=self.profile.temperature,
                )

                msg = resp.choices[0].message
                tc_dicts = None
                if msg.tool_calls:
                    tc_dicts = [
                        {
                            "id": tc.id,
                            "type": tc.type,
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in msg.tool_calls
                    ]
                self.mem.add("assistant", msg.content, tool_calls=tc_dicts)

                if not msg.tool_calls:
                    self._save_checkpoint(step + 1, self.mem.snapshot())
                    # Auto-build Merkle artifact manifest at conclusion
                    try:
                        build_artifact_manifest(self.mem.artifacts_dir)
                    except Exception:
                        pass
                    return msg.content or ""

                for tc in msg.tool_calls:
                    name = tc.function.name
                    args = json.loads(tc.function.arguments or "{}")
                    skill = self.reg.get(name)

                    if skill is not None:
                        # Inject authoritative case_id
                        args, cid_meta = inject_case_id(skill, args, self.mem.case_id)
                        if cid_meta["overridden"]:
                            try:
                                self.guard.audit(
                                    skill=skill,
                                    args={
                                        "llm_case_id": cid_meta["llm_value"],
                                        "canonical_case_id": self.mem.case_id,
                                    },
                                    step=step,
                                    case_id=self.mem.case_id,
                                    status="case_id_override",
                                    parent_step=last_step,
                                )
                            except TypeError:
                                self.guard.audit(skill, args, step=step, case_id=self.mem.case_id)

                    t0 = time.perf_counter()
                    if skill is None:
                        result = {"ok": False, "error": f"Skill '{name}' not found in registry"}
                    elif not self.guard.allow(skill, args, self.profile):
                        result = {"ok": False, "error": f"blocked by guardrail: {self.guard.last_reason}"}
                        elapsed_ms = (time.perf_counter() - t0) * 1000.0
                        self.guard.audit(
                            skill,
                            args,
                            step=step,
                            case_id=self.mem.case_id,
                            result=result,
                            latency_ms=elapsed_ms,
                            parent_step=last_step,
                            status="blocked",
                        )
                    elif dry_run:
                        result = {"ok": True, "dry_run": True, "skill": name, "planned_args": args}
                        elapsed_ms = (time.perf_counter() - t0) * 1000.0
                        self.guard.audit(
                            skill,
                            args,
                            step=step,
                            case_id=self.mem.case_id,
                            result=result,
                            latency_ms=elapsed_ms,
                            parent_step=last_step,
                            status="dry_run",
                        )
                    else:
                        result = self.exec.run(skill, args)
                        elapsed_ms = (time.perf_counter() - t0) * 1000.0
                        status_str = "ok" if result.get("ok", True) else "error"
                        self.guard.audit(
                            skill,
                            args,
                            step=step,
                            case_id=self.mem.case_id,
                            result=result,
                            latency_ms=elapsed_ms,
                            parent_step=last_step,
                            status=status_str,
                        )
                        artifact_seq += 1
                        self.mem.save_artifact(f"{artifact_seq:03d}_{name}.json", result, raw=True)

                    last_step = step
                    self.mem.add(
                        "tool",
                        json.dumps(result, ensure_ascii=False),
                        tool_call_id=tc.id,
                        name=name,
                    )

                self._save_checkpoint(step + 1, self.mem.snapshot())

            # Auto-build Merkle artifact manifest if step limit reached
            try:
                build_artifact_manifest(self.mem.artifacts_dir)
            except Exception:
                pass
            return "⚠️ เกินจำนวนก้าวสูงสุด — ต้องการคำสั่งเพิ่มเติมจากผู้ใช้"

        except KeyboardInterrupt:
            self._save_checkpoint(step + 1, self.mem.snapshot())
            print(f"\n[⏸] Interrupted at step {step + 1}. Checkpoint saved. Resume with --resume")
            raise
        except Exception as e:
            # Audit recording for forensic accountability during crash/failure
            dummy_skill = skill or self.reg.get("unknown")
            if dummy_skill:
                self.guard.audit(
                    dummy_skill,
                    {"unhandled_exception": str(e)},
                    step=step,
                    case_id=self.mem.case_id,
                    result={"ok": False, "error": str(e)},
                    status="failed",
                )
            self._save_checkpoint(step + 1, self.mem.snapshot())
            raise
