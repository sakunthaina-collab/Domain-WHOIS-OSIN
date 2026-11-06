from __future__ import annotations
import argparse
import json
import os
import pathlib
import sys
import yaml

from core.anchor import Anchor
from core.artifact_manifest import build_artifact_manifest, verify_artifacts
from core.executor import Executor
from core.guardrails import Guardrails
from core.llm import DeepSeekLLM
from core.memory import Memory
from core.orchestrator import Orchestrator
from core.registry import Profile, Registry
from core.router import Router
from core.run_manifest import compare_with_current, create_manifest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Trustworthy Multi-Profile Forensic Agent")
    parser.add_argument("--profile", default="investigator", choices=["investigator", "growth", "engineer", "biosci"])
    parser.add_argument("--case-id", default="2026-11-05-CASE-001")
    parser.add_argument("--task", default="ตรวจสอบเบอร์ +66942638165 และเครือข่ายที่เชื่อมโยง จัดทำสำนวนส่งตำรวจ")
    parser.add_argument("--escalate", action="store_true", help="Escalate to DeepSeek V4 Pro")
    parser.add_argument("--dry-run", action="store_true", help="Plan and audit without executing skills")
    parser.add_argument("--resume", action="store_true", help="Resume execution from checkpoint")
    parser.add_argument("--replay", type=str, default=None, metavar="CASE_ID", help="Replay a previous case using its 00_run_manifest.json")
    parser.add_argument("--compare-hash", action="store_true", help="When replaying, verify artifact hashes against original manifest")
    parser.add_argument("--verify-artifacts", type=str, default=None, metavar="CASE_ID", help="Verify Merkle root and SHA256 integrity of a case's artifacts")
    parser.add_argument("--include-stubs", action="store_true", help="Include markdown-only stub skills in Registry")
    parser.add_argument("--list-skills", action="store_true", help="List loaded runnable skills and exit")
    parser.add_argument("--list-profiles", action="store_true", help="List available agent profiles and exit")
    args = parser.parse_args()

    base_dir = pathlib.Path(__file__).resolve().parent
    os.chdir(base_dir)

    cfg = yaml.safe_load((base_dir / "config.yaml").read_text(encoding="utf-8"))

    if args.verify_artifacts:
        target_dir = base_dir / cfg["paths"]["artifacts"] / args.verify_artifacts
        issues = verify_artifacts(target_dir)
        if not issues:
            print(f"[PASS] Artifact integrity verified for case '{args.verify_artifacts}' (Merkle root matched, 0 tampering).")
            sys.exit(0)
        else:
            print(f"[FAIL] Artifact verification failed with {len(issues)} issue(s):")
            for issue in issues:
                print(f"  ❌ {issue}")
            sys.exit(1)

    reg = Registry(cfg["paths"]["skills"], include_stubs=args.include_stubs)

    if args.list_profiles:
        for p_file in sorted((base_dir / "profiles").glob("*.yaml")):
            p = Profile.from_yaml(p_file)
            print(f"- {p_file.stem:14s} | {p.name:20s} | model={p.model} | categories={p.categories}")
        return

    if args.list_skills:
        for name, s in sorted(reg.skills.items()):
            print(f"- {name:38s} | cat={s.category:14s} | risk={s.risk:6s} | status={s.status}")
        print(f"\nTotal runnable skills loaded: {len(reg.skills)} (total manifests: {len(reg.all_loaded)})")
        return

    target_case_id = args.replay if args.replay else args.case_id
    profile_name = args.profile
    task_desc = args.task
    seed_val = 42

    if args.replay:
        manifest_file = base_dir / cfg["paths"]["artifacts"] / args.replay / "00_run_manifest.json"
        if not manifest_file.exists():
            print(f"[ERROR] Cannot replay: {manifest_file} not found.")
            sys.exit(1)
        saved_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        saved_prof = saved_manifest.get("profile", "investigator")
        if isinstance(saved_prof, dict):
            profile_name = saved_prof.get("name", "investigator").lower().split()[0]
        else:
            profile_name = str(saved_prof).lower().split()[0]
        if profile_name not in ["investigator", "growth", "engineer", "biosci"]:
            profile_name = "investigator"
        task_desc = saved_manifest.get("task", task_desc)
        seed_val = saved_manifest.get("llm_params", {}).get("seed", 42)

        profile = Profile.from_yaml(base_dir / "profiles" / f"{profile_name}.yaml")
        profile.seed = seed_val
        profile.temperature = saved_manifest.get("llm_params", {}).get("temperature", profile.temperature)
        profile.top_k = saved_manifest.get("llm_params", {}).get("top_k", profile.top_k)

        diffs = compare_with_current(saved_manifest, profile, reg, cfg["llm"])
        if diffs:
            print("⚠️  Warning: Environment/Registry differs from original run manifest:")
            for d in diffs:
                print(f"  - {d}")
        else:
            print("[*] Replay verification: Environment and Registry hash match original manifest 100%.")
    else:
        profile = Profile.from_yaml(base_dir / "profiles" / f"{profile_name}.yaml")
        profile.seed = seed_val

    llm = DeepSeekLLM(
        base_url=cfg["llm"]["base_url"],
        api_key=os.environ.get(cfg["llm"]["api_key_env"], ""),
    )

    router = Router(reg, allowed_categories=profile.categories)
    execu = Executor(sandbox=cfg["paths"]["sandbox"])
    guard = Guardrails(
        log_path=pathlib.Path(cfg["paths"]["logs"]) / "audit.jsonl",
        case_id=target_case_id,
        artifacts_root=cfg["paths"]["artifacts"],
    )
    mem = Memory(case_id=target_case_id, artifacts_root=cfg["paths"]["artifacts"])

    routed_preview = router.route(
        task_desc,
        k=profile.top_k,
        exclude_unconfirmed=profile.guardrails.get("require_confirm", []),
    )

    # Save reproducible run manifest
    create_manifest(
        case_id=target_case_id,
        profile=profile,
        task=task_desc,
        registry=reg,
        router=router,
        llm_config=cfg["llm"],
        seed=seed_val,
        artifacts_root=cfg["paths"]["artifacts"],
    )

    print(
        f"[*] Loaded Registry: {len(reg.skills)} runnable skills "
        f"(excluded {len(reg.all_loaded) - len(reg.skills)} stubs; "
        f"{len(router.pool)} in profile '{profile.name}')"
    )
    print(f"[*] Top Routed Skills for task: {routed_preview[:6]}")

    agent = Orchestrator(llm, reg, router, execu, mem, guard, profile)
    output = agent.run(task_desc, escalate=args.escalate, dry_run=args.dry_run, resume=args.resume)
    print("\n" + output)

    # Automatically build / refresh artifact manifest with Merkle root
    manifest_data = build_artifact_manifest(mem.artifacts_dir)
    print(f"\n[*] Artifact Integrity Manifest created: {manifest_data['file_count']} files, Merkle Root = {manifest_data['merkle_root'][:16]}...")

    # External anchoring of audit chain
    anchor_cfg = cfg.get("anchor", {"adapter": "git"})
    anchor = Anchor(
        adapter=anchor_cfg.get("adapter", "git"),
        ledger_path=anchor_cfg.get("ledger_path", "logs/anchor_ledger.json"),
        **{k: v for k, v in anchor_cfg.items() if k not in ("adapter", "ledger_path")},
    )
    try:
        rec = anchor.anchor(case_id=target_case_id, audit_path=str(guard.log_path))
        gpg_status = f" (GPG signed, key={(rec.get('fingerprint') or 'default')[:16]}...)" if rec.get("signed") else " (unsigned)"
        print(f"⚓ Anchored: head={rec['head_hash'][:16]}... n={rec['entry_count']} via {rec['adapter']}{gpg_status}")
    except ValueError as e:
        print(f"⚠️  anchor skipped: {e}")

    if args.replay and args.compare_hash:
        issues = verify_artifacts(mem.artifacts_dir)
        if not issues:
            print(f"[PASS] Replay reproducibility check: All artifacts match cryptographic Merkle root.")
        else:
            print(f"[WARN] Replay differences detected: {issues}")


if __name__ == "__main__":
    main()
