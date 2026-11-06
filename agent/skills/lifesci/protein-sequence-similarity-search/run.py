import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\science\skills\protein_sequence_similarity_search\SKILL.md")
    return {
        "ok": True,
        "skill": "protein-sequence-similarity-search",
        "category": "lifesci",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
