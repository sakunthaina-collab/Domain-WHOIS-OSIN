import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\firebase\skills\xcode_project_setup\SKILL.md")
    return {
        "ok": True,
        "skill": "xcode-project-setup",
        "category": "engineering",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
