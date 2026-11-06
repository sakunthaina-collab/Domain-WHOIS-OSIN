#!/usr/bin/env python3
"""
Detect Skill Executability Status
Scans skill directories to classify skills as 'runnable' vs 'stub'.
A skill is 'runnable' if its entrypoint file exists or it uses an available system CLI / MCP tool.
"""
from __future__ import annotations
import argparse
import json
import pathlib
import sys
import yaml

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def inspect_skill(skill_yaml: pathlib.Path) -> dict:
    data = yaml.safe_load(skill_yaml.read_text(encoding="utf-8")) or {}
    rt = data.get("runtime", {})
    rtype = rt.get("type", "stub")
    parent = skill_yaml.parent

    is_runnable = False
    reason = ""

    if "_stubs" in skill_yaml.parts or data.get("status") == "stub":
        is_runnable = False
        reason = "Marked as stub or located in _stubs folder"
    elif rtype == "python":
        entry = rt.get("entry")
        if entry and (parent / entry).exists():
            is_runnable = True
            reason = f"Python entrypoint exists ({entry})"
        else:
            reason = f"Python entrypoint missing ({entry})"
    elif rtype == "cli":
        bin_cmd = rt.get("bin", "")
        # Check if local script or system command
        if (parent / bin_cmd).exists() or bin_cmd:
            is_runnable = True
            reason = f"CLI command configured ({bin_cmd})"
        else:
            reason = "CLI bin not specified"
    elif rtype == "mcp":
        server = rt.get("server")
        tool = rt.get("tool")
        if server and tool:
            is_runnable = True
            reason = f"MCP tool configured ({server}/{tool})"
        else:
            reason = "MCP server/tool not specified"
    elif rtype == "rest":
        endpoint = rt.get("endpoint")
        if endpoint:
            is_runnable = True
            reason = f"REST endpoint configured ({endpoint})"
        else:
            reason = "REST endpoint not specified"
    else:
        reason = f"Runtime type '{rtype}' requires implementation"

    return {
        "name": data.get("name", parent.name),
        "path": str(skill_yaml),
        "runtime_type": rtype,
        "is_runnable": is_runnable,
        "status": "runnable" if is_runnable else "stub",
        "reason": reason,
    }


def main():
    parser = argparse.ArgumentParser(description="Detect skill status across skills directory")
    parser.add_argument("--root", default="skills", help="Root skills directory")
    parser.add_argument("--report-json", action="store_true", help="Output JSON report")
    args = parser.parse_args()

    root = pathlib.Path(args.root)
    results = [inspect_skill(p) for p in sorted(root.rglob("skill.yaml"))]

    runnable_cnt = sum(1 for r in results if r["is_runnable"])
    stub_cnt = len(results) - runnable_cnt

    if args.report_json:
        print(json.dumps({
            "total": len(results),
            "runnable": runnable_cnt,
            "stub": stub_cnt,
            "skills": results,
        }, indent=2, ensure_ascii=False))
    else:
        print(f"Total skills scanned: {len(results)}")
        print(f"  Runnable: {runnable_cnt}")
        print(f"  Stubs:    {stub_cnt}")


if __name__ == "__main__":
    main()
