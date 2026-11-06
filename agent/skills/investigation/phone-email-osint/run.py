import json
import pathlib
import subprocess
import sys
from datetime import datetime, timezone


def run(target: str, target_type: str = "phone", passive_only: bool = True, **kwargs):
    if not passive_only:
        raise ValueError("OPSEC violation: passive_only must be True for phone-email-osint")

    inspector_script = pathlib.Path.home() / ".gemini/config/plugins/phone-email-osint/scripts/osint_inspector.py"
    if inspector_script.exists():
        proc = subprocess.run(
            [sys.executable, str(inspector_script), target],
            capture_output=True,
            text=True,
            timeout=30,
            encoding="utf-8",
        )
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout)
            data["passive_only"] = True
            return {"ok": True, "source": str(inspector_script), "data": data}

    return {
        "ok": True,
        "target": target,
        "target_type": target_type,
        "passive_only": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
