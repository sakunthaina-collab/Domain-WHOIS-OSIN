import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\skills\skills\.curated\hatch-pet\SKILL.md")
    return {
        "ok": True,
        "skill": "hatch-pet",
        "category": "external",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
