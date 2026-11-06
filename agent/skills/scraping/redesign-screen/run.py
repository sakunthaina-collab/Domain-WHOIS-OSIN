import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\mobbin\skills\redesign-screen\SKILL.md")
    return {
        "ok": True,
        "skill": "redesign-screen",
        "category": "scraping",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
