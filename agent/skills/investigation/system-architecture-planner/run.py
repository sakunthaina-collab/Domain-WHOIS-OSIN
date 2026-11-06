import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\skills\system-architecture-planner\SKILL.md")
    return {
        "ok": True,
        "skill": "system-architecture-planner",
        "category": "investigation",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
