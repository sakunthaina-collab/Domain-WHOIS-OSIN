# tests/properties/test_merkle_properties.py
"""Property-based tests for core/artifact_manifest.py Merkle root integrity."""
from __future__ import annotations
import string
from hypothesis import given
from hypothesis import strategies as st

from core.artifact_manifest import build_artifact_manifest, verify_artifacts

# Strategy for generating a set of pseudo artifact files
st_filename = st.text(alphabet=string.ascii_lowercase + string.digits + "_", min_size=1, max_size=12).map(lambda s: f"{s}.json")
st_file_content = st.text(alphabet=string.ascii_letters + string.digits + " \n\t{}", min_size=1, max_size=500)

@st.composite
def strategy_artifact_files(draw, min_files=1, max_files=8):
    files = draw(st.dictionaries(keys=st_filename, values=st_file_content, min_size=min_files, max_size=max_files))
    return files


# ---------------------------------------------------------------------------
# Property 1: Determinism
# Calling build_artifact_manifest on identical directory contents produces the exact same root
# ---------------------------------------------------------------------------
@given(files=strategy_artifact_files(min_files=1, max_files=6))
def test_merkle_root_determinism(tmp_path_factory, files):
    tmp_dir = tmp_path_factory.mktemp("merkle_prop1")
    for fname, content in files.items():
        (tmp_dir / fname).write_text(content, encoding="utf-8")
        
    m1 = build_artifact_manifest(tmp_dir)
    m2 = build_artifact_manifest(tmp_dir)
    
    assert m1["merkle_root"] == m2["merkle_root"]
    assert m1["file_count"] == m2["file_count"]
    assert m1["files"] == m2["files"]


# ---------------------------------------------------------------------------
# Property 2: Avalanche Effect / Single-Byte Mutation Detection
# Any single byte alteration in any artifact file breaks the Merkle root match
# ---------------------------------------------------------------------------
@given(
    files=strategy_artifact_files(min_files=1, max_files=6),
    data=st.data(),
)
def test_merkle_mutation_detected(tmp_path_factory, files, data):
    tmp_dir = tmp_path_factory.mktemp("merkle_prop2")
    for fname, content in files.items():
        (tmp_dir / fname).write_text(content, encoding="utf-8")
        
    orig_manifest = build_artifact_manifest(tmp_dir)
    orig_root = orig_manifest["merkle_root"]
    
    # Pick a random file to mutate
    target_fname = data.draw(st.sampled_from(list(files.keys())))
    target_file = tmp_dir / target_fname
    
    # Mutate by appending or replacing a byte
    curr_content = target_file.read_text(encoding="utf-8")
    target_file.write_text(curr_content + "!", encoding="utf-8")
    
    new_manifest = build_artifact_manifest(tmp_dir)
    assert new_manifest["merkle_root"] != orig_root, "Merkle root failed to change after file content mutation!"
    
    # Also verify_artifacts detects the tamper if original manifest was saved
    (tmp_dir / "artifact_manifest.json").write_text(
        __import__("json").dumps(orig_manifest), encoding="utf-8"
    )
    issues = verify_artifacts(tmp_dir)
    assert len(issues) > 0, "verify_artifacts failed to report tampering on mutated file!"


# ---------------------------------------------------------------------------
# Property 3: Empty Directory Invariant
# Empty directory produces predictable empty root and zero false tamper alerts
# ---------------------------------------------------------------------------
def test_empty_directory_invariant(tmp_path):
    m = build_artifact_manifest(tmp_path)
    assert m["file_count"] == 0
    assert m["files"] == []
    assert len(m["merkle_root"]) == 64
    
    issues = verify_artifacts(tmp_path)
    assert len(issues) == 0
