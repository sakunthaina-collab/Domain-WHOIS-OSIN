from __future__ import annotations
import pathlib
import sys
import pytest

AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from core.resilience import ResilientLLM, Checkpoint


class MockFailingLLM:
    def __init__(self, fail_count: int):
        self.fail_count = fail_count
        self.calls = 0

    def chat(self, *args, **kwargs):
        self.calls += 1
        if self.calls <= self.fail_count:
            raise ConnectionError("Transient network timeout")
        return {"choices": [{"message": {"content": "Success after retry"}}]}


def test_resilient_llm_recovers_after_retry():
    mock_llm = MockFailingLLM(fail_count=2)
    # fast backoff for tests
    resilient = ResilientLLM(mock_llm, max_retries=3, backoff_delays=(0.01, 0.02, 0.04))

    result = resilient.chat(messages=[{"role": "user", "content": "hi"}])
    assert result["choices"][0]["message"]["content"] == "Success after retry"
    assert mock_llm.calls == 3


def test_resilient_llm_raises_when_retries_exceeded():
    mock_llm = MockFailingLLM(fail_count=5)
    resilient = ResilientLLM(mock_llm, max_retries=2, backoff_delays=(0.01, 0.02))

    with pytest.raises(ConnectionError, match="Transient network timeout"):
        resilient.chat(messages=[{"role": "user", "content": "hi"}])


def test_checkpoint_save_and_load(tmp_path):
    cp_path = tmp_path / "test_cp.json"
    cp = Checkpoint(cp_path)

    assert cp.load() is None

    test_data = {"step": 4, "state": {"mem": ["msg1", "msg2"]}}
    cp.save(test_data)

    loaded = cp.load()
    assert loaded is not None
    assert loaded["step"] == 4
    assert loaded["state"]["mem"] == ["msg1", "msg2"]
