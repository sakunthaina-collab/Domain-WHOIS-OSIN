import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\skills\drawio-skill\SKILL.md")
    return {
        "ok": True,
        "skill": "drawio-skill",
        "category": "docs",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
