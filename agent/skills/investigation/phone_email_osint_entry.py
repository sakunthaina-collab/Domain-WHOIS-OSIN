import importlib.util
import pathlib

_run_py = pathlib.Path(__file__).resolve().parent / "phone-email-osint" / "run.py"
_spec = importlib.util.spec_from_file_location("phone_email_osint_run", _run_py)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
phone_email_osint = _mod.run
