import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\science\skills\human_protein_atlas_database\SKILL.md")
    return {
        "ok": True,
        "skill": "human-protein-atlas-database",
        "category": "lifesci",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
