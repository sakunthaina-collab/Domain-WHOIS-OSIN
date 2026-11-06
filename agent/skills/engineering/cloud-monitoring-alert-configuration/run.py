import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\google-skills\skills\cloud\cloud-monitoring-alert-configuration\SKILL.md")
    return {
        "ok": True,
        "skill": "cloud-monitoring-alert-configuration",
        "category": "engineering",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
