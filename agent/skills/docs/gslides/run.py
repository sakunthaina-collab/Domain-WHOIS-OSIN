import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\gslides\skills\gslides\SKILL.md")
    return {
        "ok": True,
        "skill": "gslides",
        "category": "docs",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
