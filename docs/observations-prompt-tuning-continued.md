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

*(See `observations-prompt-tuning.md` for iterations 1-4)*

---

## Remaining Issues to Address

- [ ] JSON synthesis prohibition needs stronger language — current wording is not constraining the model
- [ ] External ID (SEC03-BP05) keyword trigger needed for "third party" / "federated" / "IdP" scenarios
- [ ] Consider stripping JSON examples from knowledge files entirely to prevent synthesis
- [ ] Structural fabrication (numbered sections, subsections) needs explicit prohibition
- [ ] Gap between WAF compliance (75%) and knowledge grounding (30%) suggests training data leakage
- [ ] `max_tokens` hard ceiling should be tested (e.g., 500) to force brevity
- [ ] Detection/logging guidance (SEC04) consistently omitted — may need keyword trigger

---

*Last updated: 2026-02-07*
