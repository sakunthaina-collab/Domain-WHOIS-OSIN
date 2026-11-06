import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\science\skills\cheminformatics_physics\SKILL.md")
    return {
        "ok": True,
        "skill": "cheminformatics-physics",
        "category": "lifesci",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
