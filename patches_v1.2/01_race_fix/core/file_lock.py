"""Cross-platform inter-process file lock (exclusive)."""
import contextlib
import os
import pathlib
from typing import IO


@contextlib.contextmanager
def file_lock(path: str | pathlib.Path, timeout: float = 30.0):
    """Acquire exclusive OS-level lock on `path`. Blocks until available."""
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    f = open(path, "a+b")
    try:
        _acquire(f, timeout)
        yield f
    finally:
        try:
            _release(f)
        finally:
            f.close()


def _acquire(f: IO[bytes], timeout: float) -> None:
    import time
    deadline = time.monotonic() + timeout
    if os.name == "nt":
        import msvcrt
        while True:
            try:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"file lock timeout: {f.name}")
                time.sleep(0.01)
    else:
        import fcntl
        while True:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"file lock timeout: {f.name}")
                time.sleep(0.01)


def _release(f: IO[bytes]) -> None:
    if os.name == "nt":
        import msvcrt
        try:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    else:
        import fcntl
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
