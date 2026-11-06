import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\science\skills\alphagenome_variant_impact_score\SKILL.md")
    return {
        "ok": True,
        "skill": "alphagenome-variant-impact-score",
        "category": "lifesci",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
