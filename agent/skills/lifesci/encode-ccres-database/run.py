import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\science\skills\encode_ccres_database\SKILL.md")
    return {
        "ok": True,
        "skill": "encode-ccres-database",
        "category": "lifesci",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
