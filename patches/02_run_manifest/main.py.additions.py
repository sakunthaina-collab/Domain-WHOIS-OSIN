# additions to main.py for run_manifest integration

# 1. Imports:
from core.run_manifest import create_manifest, compare_with_current

# 2. CLI flags added to argparse in main():
# parser.add_argument("--replay", type=str, default=None, metavar="CASE_ID", help="Replay a previous case using its 00_run_manifest.json")
# parser.add_argument("--compare-hash", action="store_true", help="When replaying, verify artifact hashes against original manifest")

# 3. Before orchestrator.run():
# manifest = create_manifest(
#     case_id=target_case_id,
#     profile=profile,
#     task=task_desc,
#     registry=reg,
#     router=router,
#     llm_config=cfg["llm"],
#     seed=seed_val,
#     artifacts_root=cfg["paths"]["artifacts"],
# )

# 4. Replay support handling:
# if args.replay:
#     manifest_file = base_dir / cfg["paths"]["artifacts"] / args.replay / "00_run_manifest.json"
#     saved_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
#     diffs = compare_with_current(saved_manifest, profile, reg, cfg["llm"])
