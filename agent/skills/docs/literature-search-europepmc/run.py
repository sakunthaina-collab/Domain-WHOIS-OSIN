import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\science\skills\literature_search_europepmc\SKILL.md")
    return {
        "ok": True,
        "skill": "literature-search-europepmc",
        "category": "docs",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
