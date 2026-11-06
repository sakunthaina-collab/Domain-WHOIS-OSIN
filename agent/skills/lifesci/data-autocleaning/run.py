import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\data-agent-kit-plugin\skills\data-autocleaning\SKILL.md")
    return {
        "ok": True,
        "skill": "data-autocleaning",
        "category": "lifesci",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
