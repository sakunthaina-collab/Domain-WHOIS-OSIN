# additions to core/orchestrator.py for run_manifest & artifact_manifest integration

# 1. Imports:
from core.artifact_manifest import build_artifact_manifest
from core.resilience import ResilientLLM, Checkpoint

# 2. In Orchestrator.__init__:
# Wrap LLM with ResilientLLM:
# self.llm = ResilientLLM(llm, max_retries=3, base_delay=1.0)

# 3. Checkpoint methods on Orchestrator:
# def _checkpoint_path(self) -> pathlib.Path:
#     return pathlib.Path("checkpoints") / f"{self.mem.case_id}.json"
#
# def _save_checkpoint(self, step: int, state: dict[str, Any]):
#     cp = Checkpoint(self._checkpoint_path())
#     cp.save({"step": step, "state": state, "case_id": self.mem.case_id})
#
# def _load_checkpoint(self) -> dict[str, Any] | None:
#     cp = Checkpoint(self._checkpoint_path())
#     return cp.load()

# 4. In Orchestrator.run when finishing steps:
# try:
#     build_artifact_manifest(self.mem.artifacts_dir)
# except Exception:
#     pass
