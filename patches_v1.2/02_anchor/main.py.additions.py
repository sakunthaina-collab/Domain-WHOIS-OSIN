# ══════════════════════════════════════════════════════════
# INSERT INTO main.py
# ══════════════════════════════════════════════════════════
from core.anchor import Anchor

# ── 1) หลัง agent.run() เสร็จ + build_manifest() ──
anchor_cfg = cfg.get("anchor", {"adapter": "git"})
anchor = Anchor(
    adapter=anchor_cfg.get("adapter", "git"),
    ledger_path=anchor_cfg.get("ledger_path", "logs/anchor_ledger.json"),
    **{k: v for k, v in anchor_cfg.items()
       if k not in ("adapter", "ledger_path")}
)
try:
    rec = anchor.anchor(case_id=target_case_id,
                        audit_path=str(guard.log_path))
    print(f"⚓ Anchored: head={rec['head_hash'][:16]}... "
          f"n={rec['entry_count']} via {rec['adapter']}")
except ValueError as e:
    print(f"⚠️  anchor skipped: {e}")
