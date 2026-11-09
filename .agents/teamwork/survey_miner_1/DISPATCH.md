## 2026-11-06T09:54:39Z
You are survey_miner_1, a teamwork_spec_miner subagent.
Working directory: C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\.agents\teamwork\survey_miner_1
You must read ORIGINAL_REQUEST.md before starting work:
C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\.agents\teamwork\ORIGINAL_REQUEST.md

Task:
Perform a comprehensive specification survey of the requirements for developing 5 production-grade OSINT skills for Trustworthy Agent v1.5.0:
1. Examine all existing skill definitions, schemas, and specifications in `skills/investigation/`, `agent/skills/investigation/`, `agent/artifacts/`, and any related documentation.
2. Detail the exact specifications, schemas (input and output), and requirements for:
   - Tier 1:
     * Domain/WHOIS OSINT (`domain-whois-osint`): WHOIS, DNS, crt.sh, scam heuristic (0-100 numeric score, weighted signals, confidence level, bilingual reasons `top_reason_th` and `top_reason_en`), cross-skill invocation to IP skill.
     * IP Geolocation OSINT: 100% free public lookups, callable by Domain skill.
     * Email OSINT: 100% free, no API keys required.
   - Tier 2:
     * Phone OSINT: Configurable API keys via environment variables with graceful fallback / error handling when keys absent.
     * Breach Check: Configurable API keys via environment variables with graceful fallback / error handling when keys absent.
3. Detail the exact evidence tracking attributes required on findings/claims: source URL/query, timestamp, response sha256 hash.
4. Detail the structured forensic output format and how skills integrate with Trustworthy Agent's cryptographic audit hash chain, Merkle ledger, and tamper-evident reporting pipeline.
5. Identify all constraints, edge cases, and acceptance criteria from specifications.

Write your comprehensive findings to `C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\.agents\teamwork\survey_miner_1\spec_report.md`.
Also write `handoff.md` in your working directory and notify the parent orchestrator via send_message.
Do NOT modify any source code files or tests. You are read-only.
