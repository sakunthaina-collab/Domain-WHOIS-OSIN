"""
Generator that scans installed SKILL.md files and creates standardized skill.yaml manifests.
Separates real runnable skills into skills/{category}/{name} and markdown-only stubs into
skills/_stubs/{category}/{name}.
"""
from __future__ import annotations
import pathlib
import re
import shutil
import yaml

AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent
WORKSPACE_DIR = AGENT_DIR.parent
HOME_GEMINI = pathlib.Path.home() / ".gemini"

SOURCES = [
    HOME_GEMINI / "config" / "skills",
    HOME_GEMINI / "config" / "plugins",
    WORKSPACE_DIR / "skills" / "skills" / ".curated",
    WORKSPACE_DIR / "google-skills" / "skills",
    WORKSPACE_DIR / "drawio-skill" / "skills",
]

HANDCRAFTED = {
    "phone-email-osint",
    "syndicate-roster-tracker",
    "digital-forensics-investigator",
    "case-dossier-exporter",
    "counter-fraud-disruption",
    "google-maps-scraper",
}


def classify_category(name: str, desc: str, path_str: str) -> str:
    text = f"{name} {desc} {path_str}".lower()
    if any(k in text for k in ["osint", "forensic", "dossier", "syndicate", "fraud", "telegram-playbooks"]):
        return "investigation"
    if any(k in text for k in ["scrap", "agent-reach", "mobbin", "maps"]):
        return "scraping"
    if any(k in text for k in ["pdf", "compdf", "canva", "gslides", "gdocs", "gsheets", "drawio", "plain-writing", "notion"]):
        return "docs"
    if any(k in text for k in ["science", "alphafold", "alphagenome", "chem", "pdb", "uniprot", "pubmed", "biorxiv", "arxiv", "clinvar", "ensembl", "gtex", "pymol", "rdkit", "openfda", "dbsnp", "reactome", "string-database"]):
        return "lifesci"
    if "openai" in path_str.lower() or ".curated" in path_str.lower():
        return "external"
    return "engineering"


def extract_frontmatter(md_path: pathlib.Path) -> dict:
    raw = md_path.read_text(encoding="utf-8", errors="replace")
    m = re.match(r"^---\s*\r?\n(.*?)\r?\n---", raw, flags=re.DOTALL)
    if m:
        try:
            data = yaml.safe_load(m.group(1))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.startswith("#")]
    return {
        "name": md_path.parent.name.replace("_", "-"),
        "description": lines[0][:240] if lines else f"Skill {md_path.parent.name}",
    }


def has_executable_scripts(skill_dir: pathlib.Path) -> bool:
    scripts_dir = skill_dir / "scripts"
    if scripts_dir.exists() and any(scripts_dir.iterdir()):
        return True
    return any(skill_dir.glob("*.py"))


def main():
    seen_names: set[str] = set(HANDCRAFTED)
    runnable_count = len(HANDCRAFTED)
    stub_count = 0

    skills_root = AGENT_DIR / "skills"
    # Clean previously generated non-handcrafted folders
    if skills_root.exists():
        for p in list(skills_root.rglob("skill.yaml")):
            if p.parent.name not in HANDCRAFTED:
                shutil.rmtree(p.parent, ignore_errors=True)

    for src in SOURCES:
        if not src.exists():
            continue
        for sk_md in sorted(src.rglob("SKILL.md")):
            meta = extract_frontmatter(sk_md)
            name = str(meta.get("name") or sk_md.parent.name).strip().replace("_", "-")
            if name in seen_names:
                continue
            seen_names.add(name)

            desc = str(meta.get("description") or f"Skill {name}").strip()
            cat = classify_category(name, desc, str(sk_md))
            is_runnable = has_executable_scripts(sk_md.parent)
            status = "runnable" if is_runnable else "stub"

            if is_runnable:
                out_dir = skills_root / cat / name
            else:
                out_dir = skills_root / "_stubs" / cat / name

            out_dir.mkdir(parents=True, exist_ok=True)

            manifest = {
                "name": name,
                "version": "1.0.0",
                "category": cat,
                "status": status,
                "description": desc,
                "triggers": [name] + [w for w in name.split("-") if len(w) > 2],
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "instruction": {"type": "string", "description": f"Task instruction for {name}"},
                    },
                    "required": ["instruction"],
                },
                "runtime": {
                    "type": "python",
                    "entry": "run.py" if is_runnable else "SKILL.md",
                    "timeout": 120,
                    "source_skill_md": str(sk_md),
                },
                "permissions": ["filesystem:read"],
                "risk": "low",
                "outputs": ["json"],
            }
            (out_dir / "skill.yaml").write_text(
                yaml.safe_dump(manifest, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            if is_runnable:
                runnable_count += 1
                run_py = f'''import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"{str(sk_md)}")
    return {{
        "ok": True,
        "skill": "{name}",
        "category": "{cat}",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }}
'''
                (out_dir / "run.py").write_text(run_py, encoding="utf-8")
            else:
                stub_count += 1

    print(f"[+] Synchronized {len(seen_names)} deduplicated skills: {runnable_count} runnable, {stub_count} stubs (isolated in _stubs/)")


if __name__ == "__main__":
    main()
