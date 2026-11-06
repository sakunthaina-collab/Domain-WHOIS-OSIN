import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\science\skills\literature_search_openalex\SKILL.md")
    return {
        "ok": True,
        "skill": "literature-search-openalex",
        "category": "docs",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
