# ═══════════════════════════════════════════════════════════════
# ADD AT TOP OF FILE
# ═══════════════════════════════════════════════════════════════
from core.case_id_injector import inject_case_id


# ═══════════════════════════════════════════════════════════════
# REPLACE THIS BLOCK (inside for tc in msg.tool_calls:)
# ═══════════════════════════════════════════════════════════════
# ── BEFORE (existing code) ──
#     name = tc.function.name
#     args = json.loads(tc.function.arguments or "{}")
#     skill = self.reg.get(name)
#     if not self.guard.allow(skill, args, self.profile):
#         result = {"ok": False, "error": "blocked by guardrail"}
#     else:
#         self.guard.audit(skill, args, step, self.mem.case_id)
#         result = self.exec.run(skill, args)
#
# ── AFTER (with case_id injection) ──
    name = tc.function.name
    args = json.loads(tc.function.arguments or "{}")
    skill = self.reg.get(name)

    # ▼ NEW: inject authoritative case_id
    args, cid_meta = inject_case_id(skill, args, self.mem.case_id)

    # ▼ NEW: audit override if LLM sent a different case_id
    if cid_meta["overridden"]:
        try:
            self.guard.audit(
                skill=skill,
                args={"llm_case_id": cid_meta["llm_value"],
                      "canonical_case_id": self.mem.case_id},
                step=step,
                case_id=self.mem.case_id,
                status="case_id_override",
            )
        except TypeError:
            # older Guardrails without status kwarg — fall back
            self.guard.audit(skill, args, step, self.mem.case_id)

    if not self.guard.allow(skill, args, self.profile):
        result = {"ok": False, "error": "blocked by guardrail"}
    else:
        self.guard.audit(skill, args, step, self.mem.case_id)
        result = self.exec.run(skill, args)
