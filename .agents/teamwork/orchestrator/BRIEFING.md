# BRIEFING — 2026-11-06T10:07:00Z

## Mission
Develop 5 production-grade OSINT skills for Trustworthy Agent v1.5.0 with full verification and zero regressions.

## 🔒 My Identity
- Archetype: teamwork_orchestrator
- Roles: orchestrator, user_liaison, human_reporter, successor
- Working directory: C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\.agents\teamwork\orchestrator
- Original parent: sentinel
- Original parent conversation ID: 590ee628-ce4f-4073-97a1-542e52c68de4

## 🔒 My Workflow
- **Pattern**: Project
- **Scope document**: C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\.agents\teamwork\PROJECT.md
1. **Decompose**: Survey completed. Decomposed into 6 Milestones in PROJECT.md.
2. **Dispatch & Execute**: Direct iteration loop (Explorer -> Worker -> Reviewer -> Challenger -> Auditor -> Gate) per Project Pattern 2B for each milestone.
3. **On failure**: Retry -> Replace -> Skip -> Redistribute -> Redesign -> Escalate
4. **Succession**: At 16 spawns, write handoff.md, spawn successor.
- **Work items**:
  0. Survey phase [done]
  1. Milestone 1: Tier 1 IP & Email Skills [in-progress]
  2. Milestone 2: Tier 1 Domain & Scam Heuristics [pending]
  3. Milestone 3: Tier 2 Phone & Breach Skills [pending]
  4. Milestone 4: Test Suite & Frozen Time Coverage [pending]
  5. Milestone 5: Audit Hash Chain & Zero Regression [pending]
  6. Milestone 6: Final Adversarial & Integrity Audit [pending]
- **Current phase**: 2B (Executing Milestone 1)
- **Current focus**: Milestone 1 (Tier 1 IP & Email Skills)

## 🔒 Key Constraints
- NEVER write, modify, or create source code files directly.
- NEVER run build/test commands yourself — require workers to do so.
- NEVER investigate or explore the problem at the code level — dispatch Explorers for technical investigation.
- You MAY use file-editing tools ONLY for metadata/state files (.md) in your .agents/teamwork/ folder.
- Integrity mode: demo
- Do NOT copy code from existing open-source projects for core logic
- Do NOT run external scripts or delegate execution to other tools outside the controlled environment
- 100% original proprietary code for core logic
- Strictly adhere to v1.4.2 Executor allowlist
- Zero regressions against existing 171 repository tests
- Forensic Auditor audit is a BINARY VETO
- Never reuse a subagent after it has delivered its handoff

## Current Parent
- Conversation ID: 590ee628-ce4f-4073-97a1-542e52c68de4
- Updated: not yet

## Key Decisions Made
- Survey completed by 3 subagents; architecture, specs, test baseline confirmed.
- Code layout confirmed: primary in `agent/skills/investigation/`, mirrored to `skills/investigation/`.
- Decomposed into 6 milestones in `.agents/teamwork/PROJECT.md`.
- Commencing Milestone 1: Tier 1 IP Geolocation OSINT & Email OSINT.

## Team Roster
| Agent | Type | Work Item | Status | Conv ID |
|-------|------|-----------|--------|---------|
| survey_miner_1 | teamwork_spec_miner | Survey OSINT specifications, schemas, heuristics | completed | 8d99c426-f3af-46a5-b36c-de0c08765119 |
| survey_explorer_1 | teamwork_explorer | Survey 171 tests, fixtures, freezegun, executor allowlist | completed | bc6d842b-ec00-4c87-91d7-6053a6ae25b0 |
| survey_explorer_2 | teamwork_explorer | Survey codebase architecture, registry, cross-skill, merkle ledger | completed | 5a8aa06f-e022-4bb5-8731-086636d8c6f1 |
| m1_spec_miner_1 | teamwork_spec_miner | M1 IP & Email spec mining & schema verification | completed | 292b0296-65b8-4b02-93b2-b6dadaa694e0 |
| m1_explorer_1 | teamwork_explorer | M1 IP Geolocation OSINT technical design | completed | 5a607f2a-43ac-45d5-a6d6-f2465fcd0e48 |
| m1_explorer_2 | teamwork_explorer | M1 Email OSINT technical design | completed | c1a39853-f8a2-48d0-a559-f3759c512ee2 |
| m1_worker_1 | teamwork_worker | Milestone 1 Implementation (IP & Email OSINT) | completed | 2e637b1b-911d-4b35-b3d3-e685ec1dce4b |
| m1_reviewer_1 | teamwork_reviewer | Milestone 1 Code Review 1 | in-progress | f1501f43-88c4-4b89-abd8-924e59f329cf |
| m1_reviewer_2 | teamwork_reviewer | Milestone 1 Code Review 2 | in-progress | 49db2d15-8926-4173-af9e-eb77974f7507 |
| m1_challenger_1 | teamwork_challenger | IP OSINT Adversarial Challenge | in-progress | ac04ca4a-4518-4a11-908b-11d6f4a74b15 |
| m1_challenger_2 | teamwork_challenger | Email OSINT Adversarial Challenge | in-progress | ce6e530f-df98-4b66-a34e-199c34439bbc |
| m1_auditor_1 | teamwork_auditor | Milestone 1 Forensic Integrity Audit | in-progress | 38951644-d9e2-4cca-99bd-807243a6f42f |

## Succession Status
- Succession required: no
- Spawn count: 12 / 16
- Pending subagents: f1501f43-88c4-4b89-abd8-924e59f329cf, 49db2d15-8926-4173-af9e-eb77974f7507, ac04ca4a-4518-4a11-908b-11d6f4a74b15, ce6e530f-df98-4b66-a34e-199c34439bbc, 38951644-d9e2-4cca-99bd-807243a6f42f
- Predecessor: none
- Successor: not yet spawned

## Active Timers
- Heartbeat cron: 55cddded-d3e8-4597-ace7-b88461de123a/task-23
- Safety timer: none
- On succession: kill all timers before spawning successor
- On context truncation: handle timers as step 4 of State Recovery

## Artifact Index
- .agents/teamwork/ORIGINAL_REQUEST.md — Authoritative user request
- .agents/teamwork/PROJECT.md — Project master plan, architecture & milestones
- .agents/teamwork/orchestrator/DISPATCH.md — Dispatch log
- .agents/teamwork/orchestrator/BRIEFING.md — Working memory
- .agents/teamwork/orchestrator/progress.md — Liveness & status tracking
