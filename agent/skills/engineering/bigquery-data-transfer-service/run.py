import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\config\plugins\data-agent-kit-plugin\skills\bigquery-data-transfer-service\SKILL.md")
    return {
        "ok": True,
        "skill": "bigquery-data-transfer-service",
        "category": "engineering",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
