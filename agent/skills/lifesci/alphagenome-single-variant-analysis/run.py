import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\science\skills\alphagenome_single_variant_analysis\SKILL.md")
    return {
        "ok": True,
        "skill": "alphagenome-single-variant-analysis",
        "category": "lifesci",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
