from __future__ import annotations
import json
import logging
import pathlib
import time
from typing import Any

logger = logging.getLogger("agent.resilience")


class ResilientLLM:
    """Wrapper for LLM client with exponential backoff and automatic retry on transient errors."""

    def __init__(
        self,
        llm: Any,
        max_retries: int = 3,
        backoff_delays: tuple[float, ...] = (1.0, 2.0, 4.0),
    ):
        self.llm = llm
        self.max_retries = max(1, max_retries)
        self.backoff_delays = backoff_delays

    def chat(self, *args: Any, **kwargs: Any) -> Any:
        last_err: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                return self.llm.chat(*args, **kwargs)
            except Exception as e:
                last_err = e
                if attempt == self.max_retries - 1:
                    logger.error("LLM call failed permanently after %d attempts: %s", self.max_retries, e)
                    raise
                delay = self.backoff_delays[min(attempt, len(self.backoff_delays) - 1)]
                logger.warning(
                    "LLM call transient failure on attempt %d/%d (%s). Retrying in %.1fs...",
                    attempt + 1,
                    self.max_retries,
                    e,
                    delay,
                )
                time.sleep(delay)
        if last_err:
            raise last_err


class Checkpoint:
    """Persistent execution state checkpoint for crash recovery and resumption."""

    def __init__(self, path: str | pathlib.Path):
        self.path = pathlib.Path(path)

    def save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return None
