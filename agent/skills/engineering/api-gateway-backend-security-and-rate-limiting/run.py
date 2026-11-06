import pathlib

def run(instruction: str = "", **kwargs):
    skill_md = pathlib.Path(r"C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\google-skills\skills\cloud\api-gateway-backend-security-and-rate-limiting\SKILL.md")
    return {
        "ok": True,
        "skill": "api-gateway-backend-security-and-rate-limiting",
        "category": "engineering",
        "status": "runnable",
        "source_skill_md": str(skill_md),
        "instruction": instruction,
    }
