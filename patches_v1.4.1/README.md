# Patch v1.4.1: Fuzz-Discovered Edge-Case Hotfix

Resolves findings discovered during Patch v1.4 Hypothesis fuzzing round 1:
- **FIND-01:** Unicode decimal digits (Devanagari, Thai, Arabic-Indic) converted to ASCII
- **FIND-02:** Embedded `+` signs removed; only leading `+` preserved
- **FIND-03:** Unicode line separators (`\x85`, `\u2028`, `\u2029`) escaped on JSONL write
- **FIND-04:** Pure chain vs anchored chain test semantics clarified and documented

## Apply

PowerShell:
```powershell
.\patches_v1.4.1\apply_all.ps1
```

Bash:
```bash
bash patches_v1.4.1/apply_all.sh
```
