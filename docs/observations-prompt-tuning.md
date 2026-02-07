# AskAnArchBot — Prompt Tuning Observations

## Overview

This document captures the iterative process of tuning the bot's system prompt to constrain responses strictly to loaded knowledge files. The goal: the bot should act as a knowledge-base-constrained advisor, not a general-purpose AI.

## Test Setup

- **Model**: Claude Sonnet 4.5 (`claude-sonnet-4-5-20250929`)
- **Knowledge file**: `bot/knowledge/aws-storage-security.md` (567 lines, WAF Security Pillar-aligned)
- **Test question (on-topic)**: "how should i use CMK properly?"
- **Test question (off-topic)**: "what is the security standards for vpcs?"
- **Review agent**: aws-security-architect (custom Claude agent for WAF compliance review)

---

## Iteration Log

### Iteration 1 — Baseline (no constraints)

**System prompt**: General InfoSec Architect persona with standard guidelines (actionable recommendations, defense in depth, concise).

**Result**:
- Off-topic (VPC): Responded with a full answer using general knowledge (not tested with refusal)
- On-topic (CMK): **2,067 tokens**, exhaustive guide with boto3 code, CLI commands, full IAM permission lists, encryption context examples
- **Agent review**: ~50-60% of content was NOT in the knowledge file. Bot was functioning as a general AWS KMS expert.

**Problem**: No guardrails. Bot supplements heavily with training data.

---

### Iteration 2 — Added knowledge-only instruction + closing line

**Changes**:
- Added: "Only use information from the Reference Knowledge section below"
- Added: "Do not generate code examples, CLI commands, or policy snippets unless they appear in the reference knowledge"
- Added: Keep responses concise
- Added closing line requirement

**Result**:
- Off-topic (VPC): **21 tokens** — clean refusal, exact message. (Pass)
- On-topic (CMK): **1,213 tokens** — still too long
- **Agent review**: ~40-50% of content still fabricated beyond the knowledge file
  - Entire "Common Mistakes to Avoid" section (5 items) — not in knowledge file
  - Entire "Validation Checklist" — not in knowledge file
  - Detailed IAM permission lists (kms:Create*, kms:Describe*, etc.) — not in knowledge file
  - Step-by-step cross-account procedures — not in knowledge file
  - CloudTrail Insights recommendation — not in knowledge file

**Problem**: "Only use information from Reference Knowledge" was too soft. The model still interpreted this loosely and expanded on concepts mentioned briefly in the knowledge file.

---

### Iteration 3 — Strict rules with explicit prohibitions

**Changes**: Rewrote guidelines as numbered "STRICT RULES":
1. Knowledge-only responses — "if a fact is not written verbatim or near-verbatim, do not include it"
2. Off-topic refusal — exact message, nothing else
3. Be brief — "do not write exhaustive guides, generate checklists, or create sections that don't exist"
4. Closing line requirement
5. No fabrication — explicitly banned code examples, CLI commands, IAM permission lists, policy snippets, step-by-step procedures, and "common mistakes" sections unless word-for-word in the knowledge

**Result**:
- On-topic (CMK): **415 tokens** — 66% reduction from iteration 2, 80% reduction from iteration 1
- **Agent review**: ~85-90% grounded in knowledge file. Grade: B+
  - Minor issues: dropped a qualifier ("for most workloads" became absolute), slightly over-prescriptive ("always use CMKs"), missing WAF reference IDs from knowledge file
  - No fabricated sections, no code examples, no checklists

**Improvement**: Significant. The explicit prohibitions and "verbatim or near-verbatim" language made the biggest difference.

---

## Key Findings

### 1. Soft instructions don't constrain LLMs effectively
Saying "only use information from the reference knowledge" is too vague. The model interprets "information" broadly — if the knowledge file mentions "key rotation", the model feels licensed to explain the full mechanics of key rotation from its training data.

### 2. Explicit prohibitions outperform positive instructions
"Do not generate checklists, common mistakes sections, or IAM permission lists" was more effective than "keep responses concise." The model needs to know what NOT to do.

### 3. "Verbatim or near-verbatim" is the key phrase
This language forced the model to stay close to the source material instead of expanding on concepts.

### 4. Token usage is a proxy for compliance
- Unconstrained: 2,067 tokens (~50% grounded)
- Soft constraints: 1,213 tokens (~55% grounded)
- Strict rules: 415 tokens (~87% grounded)

Lower token count generally correlates with better knowledge grounding.

### 5. Off-topic refusal was easy to solve
A single clear instruction with an exact refusal message worked from the first attempt. The hard problem is constraining ON-topic responses.

### 6. The model still paraphrases and editorializes
Even at 85-90% grounding, the model drops qualifiers, strengthens language ("always", "never"), and omits WAF reference IDs that exist in the source. This suggests further iteration is needed.

---

## Remaining Issues to Address

- [ ] WAF reference IDs (SEC07-BP02, etc.) should be preserved in responses
- [ ] Qualifiers from source material should not be dropped (e.g., "for most workloads")
- [ ] Absolute language ("always", "never") should only be used when the knowledge file uses it
- [ ] Consider reducing `max_tokens` in the API call as a hard ceiling
- [ ] Consider testing with different models (e.g., Haiku for faster/cheaper responses)
- [ ] Rate limiting before production use
- [ ] Test with multiple knowledge files loaded simultaneously
- [ ] Evaluate whether the knowledge file itself is too detailed (inviting expansion)

---

## Token Usage Summary

| Iteration | Constraint Level | Output Tokens | Grounding % | Agent Grade |
|-----------|-----------------|---------------|-------------|-------------|
| 1         | None            | 2,067         | ~50-60%     | Fail        |
| 2         | Soft            | 1,213         | ~55-60%     | Fail        |
| 3         | Strict          | 415           | ~85-90%     | B+          |

---

*Last updated: 2026-02-07*
