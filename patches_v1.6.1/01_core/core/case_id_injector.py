# core/case_id_injector.py
"""Inject authoritative case_id into skill args before execution.

Why: LLMs may hallucinate or copy case_id values from skill examples.
The orchestrator, not the LLM, is the source of truth for which case
a skill is operating on.
"""
from typing import Any
from core.case_id import validate_case_id


def inject_case_id(skill: Any, args: dict, case_id: str) -> tuple[dict, dict]:
    """Inject case_id into args if the skill schema declares it.

    Returns (new_args, meta) where meta is:
      - injected:   bool — whether case_id was written into args
      - overridden: bool — whether LLM provided a different value
      - llm_value:  str | None — what the LLM originally sent (truncated)

    Only injects if the skill's input_schema declares `case_id` (either
    in properties or in required list). This avoids breaking skills that
    use a different key name.
    """
    meta = {"injected": False, "overridden": False, "llm_value": None}

    schema = getattr(skill, "input_schema", None) or {}
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    required = schema.get("required", []) if isinstance(schema, dict) else []

    if "case_id" not in props and "case_id" not in required:
        return args, meta

    # Validate orchestrator's case_id (paranoid — orchestrator should
    # have validated at startup, but defense in depth)
    canonical = validate_case_id(case_id)

    new_args = dict(args)
    llm_value = new_args.get("case_id")

    if llm_value is not None and llm_value != canonical:
        meta["overridden"] = True
        meta["llm_value"] = str(llm_value)[:80]

    new_args["case_id"] = canonical
    meta["injected"] = True
    return new_args, meta
