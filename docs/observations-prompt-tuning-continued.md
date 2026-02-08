# AskAnArchBot — Prompt Tuning Observations (Continued)

## Overview

Continuation of `observations-prompt-tuning.md`. This document captures iterations 5+ using the new `response-review` agent workflow and dual-agent review process (response-review + aws-security-architect).

---

## Iteration Log

### Iteration 5 — Federation Question with Dual-Agent Review

**System prompt**: Unchanged from iteration 3 (strict rules).
**Knowledge files**: `aws-storage-security.md` + `aws-iam-security.md` (~4,250 lines total).
**Test question**: "i need to build a IAM role thats only accessiblbe by a federated user via idp"

**Review method**: Dual-agent — `response-review` (knowledge grounding) + `aws-security-architect` (WAF compliance). First use of the new review workflow.

**Result**:
- **1,105 tokens** — 2.5x the upper target of 450
- **Response-review grade**: 30/100 — Fail
- **WAF compliance**: ~75%

#### Knowledge Grounding Analysis (response-review agent)

| Metric | Value |
|--------|-------|
| Grounding | ~30% (5 of 17 claims traced to knowledge files) |
| Tokens | 1,105 (target: 150-450) |
| JSON blocks generated | 6 (only 1 exists in knowledge files) |

**Rule violations**:
- Rule 1 (Knowledge-only): Three full JSON trust policies fabricated — SAML, OIDC (diverges from knowledge file version), Identity Center/AWSSSO
- Rule 3 (Be brief): Exhaustive guide format at 1,105 tokens
- Rule 5 (No fabrication): 3 complete policy JSONs + 3 standalone condition snippets not verbatim in knowledge files

**Fabricated content**:
- SAML 2.0 trust policy JSON (not in knowledge files)
- Identity Center "AWSSSO" trust policy JSON (entirely fabricated — "AWSSSO" provider name doesn't exist in knowledge)
- OIDC trust policy (knowledge file has a GitHub OIDC example but bot's version diverges in formatting and context)
- Standalone condition snippets for MFA, IP address, OrgID (reformulated, not verbatim)
- Session duration mischaracterized: "read-only" vs knowledge file's "standard operational roles"
- "Important Security Notes" numbered checklist section (fabricated structure)

**Missing from knowledge files (should have been cited)**:
- External ID for confused deputy prevention (SEC03-BP05) — same miss as iteration 4
- Never use wildcard principal without strict conditions (line 268)
- Cognito Identity Pools as a federation mechanism (lines 1452-1467)
- Role chaining considerations (lines 304-307)
- IAM Identity Center permission set details (lines 937-963)

#### WAF Compliance Analysis (aws-security-architect agent)

**Correctly WAF-aligned**:
- SEC02-BP01 (federation preference) — correct
- SEC02-BP03 (temporary credentials) — correct
- SEC02-BP05 (MFA enforcement) — correct
- SEC03-BP02 (least privilege) — correct

**Missing WAF context**:
- SEC01 — Shared Responsibility Model for trust policy ownership
- SEC02-BP04 — Centralized identity provider (should be cited for IdP consolidation)
- SEC04 — Detection/CloudTrail for federated access logging (traceability design principle)
- SEC10 — Forensic capabilities for federated identity logs

**Non-WAF content injected**:
- Session duration specifics ("1 hour"/"12 hours") — general best practice, not WAF-prescribed values
- IP restriction pattern — valid AWS feature but not WAF-mandated for federated roles

### Iteration 6 — Rule 6 Anti-Synthesis Test

**System prompt change**: Added Rule 6 — "JSON policy examples — quote only, never synthesize." Explicitly bans combining, merging, modifying, or adapting JSON examples from different sections. If no complete example exists, describe in plain text instead.
**Knowledge files**: Unchanged (`aws-storage-security.md` + `aws-iam-security.md`).
**Test question**: Same as iteration 5 — "i need to build a IAM role thats only accessiblbe by a federated user via idp"

**Review method**: Dual-agent (response-review + aws-security-architect).

**Result**:
- **865 tokens** — down 22% from iteration 5, but still ~2x the upper target
- **Response-review grade**: 28/100 — Fail (regression from 30)
- **WAF compliance**: ~80%

#### Knowledge Grounding Analysis (response-review agent)

| Metric | Value |
|--------|-------|
| Grounding | ~25% (3 of 12 claims traced to knowledge files) |
| Tokens | 865 (target: 150-450) |
| JSON blocks generated | 4 (only 1 exists in knowledge files) |

**Rule 6 violations (new rule)**:
- SAML 2.0 trust policy JSON entirely fabricated — no SAML trust policy example exists anywhere in the knowledge files
- IP/MFA condition snippets extracted from unrelated cross-account examples and re-contextualized for federation (combining across sections)
- OIDC trust policy is a near-copy of the GitHub Actions example from knowledge (acceptable) but reframed as generic "OIDC Federation"

**Other rule violations**:
- Rule 1 (Knowledge-only): "automatic credential rotation" for federated roles not stated verbatim
- Rule 3 (Be brief): 865 tokens, nearly double upper target
- Rule 5 (No fabrication): "No long-term access keys — Federation eliminates the need for IAM users with access keys" synthesized, not verbatim

**Fabricated content**:
- Entire SAML 2.0 trust policy JSON
- Standalone IP address condition snippet (recontextualized)
- Standalone MFA condition snippet (recontextualized)
- "No long-term access keys" bullet point (synthesized)

**Missing from knowledge files (should have been cited)**:
- External ID for confused deputy prevention (SEC03-BP05) — 4th consecutive miss
- IAM Identity Center buried instead of leading (WAF recommends it as primary approach)
- Federated user checklist items from knowledge file not cited

#### WAF Compliance Analysis (aws-security-architect agent)

**Correctly WAF-aligned**:
- SEC02-BP01 (workforce identity centralization) — correct
- SEC02-BP03 (temporary credentials) — correct
- SEC04-BP01 (CloudTrail detection/traceability) — correct, new vs iteration 5
- SEC02-BP02 (eliminate long-term access keys) — correct

**Missing WAF context**:
- SEC03-BP01 — Grant least privilege access (no permission policy guidance — what the federated user can *do* once the role is assumed)
- SEC02-BP04 — Least privilege not cited for role permissions
- SEC02-BP05 — Organizations SCPs to enforce federation requirements
- SEC01-BP01 — Separate workloads using accounts for multi-account federation

**Critical gap**: Bot provides trust policy (who can assume the role) but completely ignores permission policy (what the assumed role can do). This is core to SEC03-BP01.

#### Comparison: Iteration 5 vs 6

| Metric | Iter 5 (old Rule 5) | Iter 6 (+ Rule 6) | Delta |
|--------|---------------------|---------------------|-------|
| Tokens | 1,105 | 865 | -22% |
| Grounding | ~30% | ~25% | Worse |
| Grade | 30/100 | 28/100 | Worse |
| JSON blocks | 6 | 4 | -2 blocks |
| Fabricated JSON | 5 of 6 | 3 of 4 | Same ratio (~75%) |
| WAF compliance | ~75% | ~80% | +5% |

**Bottom line**: Rule 6 reduced token count and removed 2 JSON blocks (Identity Center AWSSSO policy and OrgID condition), but the SAML trust policy fabrication persists. The model still treats "describe a federation pattern" as license to generate a plausible JSON example. The anti-synthesis instruction alone isn't enough — the model needs either a hard `max_tokens` cap or the SAML examples need to be added to the knowledge files.

---

## Key Findings (Iterations 5+)

### 10. JSON synthesis is still the dominant failure mode

Iteration 5 confirms the iteration 4 finding: the bot generated 6 JSON blocks, but only 1 (GitHub OIDC) exists in the knowledge files. The strict rule "do not generate code examples unless they appear word-for-word" is still insufficient. The model interprets combining components from across the knowledge files as acceptable, and also fabricates entirely new examples (SAML trust policy, AWSSSO provider).

### 11. Dual-agent review catches more issues than single-agent

The response-review agent focuses on knowledge grounding (what % traces to source), while the aws-security-architect agent catches missing WAF principles (SEC04 detection, SEC10 forensics) and identifies non-WAF content masquerading as WAF guidance. Together they provide a more complete picture:
- **response-review**: "30% grounded, 6 fabricated JSON blocks"
- **aws-security-architect**: "75% WAF-compliant, missing detection/logging principles"
- Both independently flagged session duration values as problematic

### 12. The External ID miss is now a confirmed pattern

Three consecutive iterations (4a, 4b, 5) have missed External ID (SEC03-BP05) despite it appearing prominently in the IAM knowledge file. This is no longer a one-off — it's a systematic blind spot. The model does not associate "federated user via IdP" with the confused deputy problem, even though the knowledge file explicitly covers this under third-party access patterns.

### 13. The bot fabricates structural elements, not just content

Beyond fabricating JSON, the bot creates organizational structures that don't exist in the knowledge files: numbered "Important Security Notes" sections, "Additional Security Restrictions" subsections, and checklist-style formatting. The strict rules eliminated "common mistakes" sections but the model found new structural patterns to generate.

### 14. WAF compliance != knowledge grounding

A response can be 75% WAF-compliant but only 30% grounded in the knowledge files. This means the bot is drawing on general WAF knowledge from its training data rather than the specific knowledge files provided. The strict rules are supposed to prevent this, but the model still supplements from training data when the knowledge files don't provide enough "material" for a complete answer.

### 15. Anti-synthesis rules reduce volume but don't prevent fabrication

Rule 6 ("quote only, never synthesize") reduced JSON blocks from 6 to 4 and tokens from 1,105 to 865. But the fabrication *ratio* stayed the same (~75% of JSON blocks are fabricated). The SAML trust policy — which has no corresponding example in the knowledge files — was still generated despite the explicit instruction "if no complete example exists, describe the guidance in plain text instead." This suggests the model doesn't evaluate whether an example exists before generating it; it generates first and the instruction acts more as a soft preference than a hard constraint.

### 16. Missing knowledge = fabrication magnet

The bot fabricates SAML trust policies because the knowledge files don't contain one. When the model has strong conceptual understanding of a topic (SAML federation) but no verbatim example to quote, it generates one anyway. This points to a potential fix: either add SAML trust policy examples to the knowledge files (so the bot can quote them) or explicitly state in the knowledge files that "no SAML trust policy example is provided — describe in plain text only." The absence of an example is interpreted as an invitation to generate one.

### 17. Permission policy is a blind spot

Both the response-review and aws-security-architect agents independently noted that the bot answers "who can assume the role" (trust policy) but never addresses "what the role can do" (permission policy). This is SEC03-BP01 and is arguably more important than the trust policy for security posture. The knowledge file may need a more prominent section linking trust policies to permission policies.

---

## Response Review Agent Workflow

### What changed

Previously, response reviews were orchestrated manually in the main conversation context — reading logs, copying responses, launching the aws-security-architect agent with a long prompt, waiting for results, summarizing back. This burned ~4,000+ tokens per review in the main context window.

### New workflow

1. Bot responds to test question
2. Launch `response-review` agent with the log file path — handles grounding analysis autonomously
3. Launch `aws-security-architect` agent with the response — handles WAF compliance check
4. Both return concise reports (~200-300 tokens each)
5. Main context cost: ~350 tokens per review (launch prompts + reports)

**Token savings**: ~90% reduction in main context tokens per review.

### Agent roles

| Agent | Focus | Catches |
|-------|-------|---------|
| `response-review` | Knowledge grounding, rule compliance, token efficiency | Fabricated content, missing knowledge file references, rule violations |
| `aws-security-architect` | WAF alignment, missing security principles | Non-WAF guidance, missing WAF best practices, incorrect WAF citations |

---

## Token Usage Summary (Continued)

| Iteration | Constraint Level | Output Tokens | Grounding % | Review Grade | WAF Compliance |
|-----------|-----------------|---------------|-------------|--------------|----------------|
| 5         | Strict + dual knowledge files | 1,105 | ~30% | Fail (30) | ~75% |
| 6         | Strict + Rule 6 (anti-synthesis) | 865 | ~25% | Fail (28) | ~80% |

*(See `observations-prompt-tuning.md` for iterations 1-4)*

---

## Remaining Issues to Address

- [ ] Anti-synthesis rule reduces volume but not fabrication ratio — need stronger approach
- [ ] Consider adding SAML trust policy examples to knowledge files (fill the gap the model keeps fabricating into)
- [ ] External ID (SEC03-BP05) keyword trigger needed — 4 consecutive misses
- [ ] Permission policy guidance (SEC03-BP01) missing from responses — knowledge file may need prominent section linking trust + permission policies
- [ ] `max_tokens` hard ceiling should be tested (e.g., 500) to force brevity
- [ ] Structural fabrication (numbered sections, subsections) needs explicit prohibition
- [ ] Gap between WAF compliance (~80%) and knowledge grounding (~25%) suggests training data leakage
- [x] ~~JSON synthesis prohibition needs stronger language~~ — Rule 6 added, helps with volume but not fabrication ratio
- [x] ~~Detection/logging guidance (SEC04) consistently omitted~~ — iteration 6 included CloudTrail mention

---

*Last updated: 2026-02-07*
