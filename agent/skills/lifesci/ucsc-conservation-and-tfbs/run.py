import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\science\skills\ucsc_conservation_and_tfbs\SKILL.md")
    return {
        "ok": True,
        "skill": "ucsc-conservation-and-tfbs",
        "category": "lifesci",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
