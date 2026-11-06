import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\data-agent-kit-plugin\skills\gcs-security-assessment\SKILL.md")
    return {
        "ok": True,
        "skill": "gcs-security-assessment",
        "category": "engineering",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
