import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\general-counsel-advisor\skills\general-counsel-advisor\SKILL.md")
    return {
        "ok": True,
        "skill": "general-counsel-advisor",
        "category": "engineering",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
