# tests/conftest.py additions
from __future__ import annotations
import os
import pathlib
import sys
from hypothesis import settings, Verbosity

# Ensure agent root is on sys.path
agent_dir = str(pathlib.Path(__file__).resolve().parent.parent)
if agent_dir not in sys.path:
    sys.path.insert(0, agent_dir)

settings.register_profile("ci", max_examples=1000, deadline=None)
settings.register_profile("dev", max_examples=200, deadline=None)
settings.register_profile("debug", max_examples=50, verbosity=Verbosity.verbose, deadline=None)
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "dev"))
