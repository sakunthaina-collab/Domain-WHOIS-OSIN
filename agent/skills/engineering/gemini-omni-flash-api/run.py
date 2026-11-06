import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\gemini-api\skills\gemini-omni-flash-api\SKILL.md")
    return {
        "ok": True,
        "skill": "gemini-omni-flash-api",
        "category": "engineering",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
