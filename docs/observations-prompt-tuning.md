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

### Iteration 4 — Multi-knowledge-file test (Storage + IAM)

**Context**: Added `aws-iam-security.md` (3,683 lines) alongside existing `aws-storage-security.md` (567 lines). System prompt unchanged from iteration 3. Total knowledge base: ~4,250 lines injected into system prompt.

**Test question**: "make a IAM recommendation for a conditional policy for a s3 bucket for a third party to access, i have their organizationID and IAM Role."

This question spans both knowledge files (S3 from storage, IAM policies/cross-account from IAM) and tests whether the bot can synthesize correctly.

**Result (first attempt, pre-IAM-expansion)**:
- **672 tokens**, two JSON policy examples
- **Agent review**: 65/100 — Fail
  - Missing External ID (SEC03-BP05) — critical for third-party access, explicitly in knowledge file
  - Speculative "Additional Recommendations" section
  - MFA in bucket policy — wrong context (belongs in trust policies)
  - Insufficient WAF citations

**Result (second attempt, post-IAM-expansion to 3,683 lines)**:
- **833 tokens** — actually *increased* despite same strict rules
- **Agent review**: 45/100 — Fail (regression)
  - **Still missing External ID** — despite it now appearing in 3 places in the IAM knowledge file (lines 269-296, 2332-2336, checklist at 3592)
  - Generated two complete JSON policies that don't exist verbatim in knowledge files (violates strict rule #5)
  - "Additional Recommendations" section fabricated from scattered concepts
  - "Optional: Additional Conditions" section entirely synthesized
  - Agent recommended response should be 150-250 tokens, not 833

**Key observations from iteration 4**:

1. **More knowledge = more synthesis, not more grounding.** Adding the expanded IAM file (3,683 lines) gave the model more raw material to synthesize from, which actually *increased* verbosity and reduced grounding. The model treats the larger knowledge base as license to combine concepts freely.

2. **The bot consistently misses External ID for third-party scenarios.** Despite SEC03-BP05 appearing prominently in the knowledge file with explicit guidance ("Use External ID for confused deputy prevention"), the bot ignores it in both attempts. This suggests the model is pattern-matching on "S3 bucket policy" rather than recognizing the "third party" keyword should trigger External ID guidance.

3. **JSON synthesis is the hardest behavior to constrain.** The strict rules successfully eliminated fabricated checklists and "common mistakes" sections, but the bot still synthesizes new JSON policies by combining components from across the knowledge files. The instruction "do not generate code examples unless they appear word-for-word" is not strong enough — the model interprets combining existing examples as acceptable.

4. **Input token bloat.** With both knowledge files, the system prompt uses ~29,000-41,000 input tokens. This increases cost and latency without improving response quality.

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

### 7. More knowledge doesn't mean better responses
Adding a 3,683-line IAM knowledge file actually made responses worse (45/100 vs 65/100 pre-expansion). The model has more material to synthesize from, which increases verbosity and fabrication. There may be a sweet spot for knowledge file size.

### 8. Keyword-triggered guidance may be needed
The bot consistently misses External ID for "third party" scenarios despite it being prominent in the knowledge file. The model may need explicit trigger instructions (e.g., "If the user mentions third-party access, always reference External ID per SEC03-BP05").

### 9. JSON synthesis is harder to constrain than text synthesis
The strict rules eliminated fabricated text sections (checklists, common mistakes) but the bot still combines JSON components from across the knowledge files into new policies. This is a distinct behavior from text fabrication and may require a separate prohibition.

---

## Using an Agent to Review Knowledge File Quality

A key part of this process was using a separate Claude agent (`aws-security-architect`) to review and validate the bot's responses and knowledge files. This created a feedback loop:

1. **Bot responds** to a user question using the knowledge file
2. **Review agent evaluates** the response against the knowledge file, identifying what was grounded vs. fabricated
3. **We adjust** the system prompt based on the agent's findings
4. **Repeat** until the grounding % is acceptable

### Why this works

The review agent has its own strict WAF-only system prompt, so it's well-positioned to judge whether the bot's output is accurate and properly scoped. It can identify:
- Content fabricated beyond the knowledge file (false grounding)
- Missing WAF references that should have been cited
- Qualifiers dropped or language strengthened beyond the source
- Structural issues (fabricated checklists, "common mistakes" sections)

### Agent-assisted knowledge file creation

We also used the aws-security-architect agent to *write* the knowledge files themselves, then had it review its own output for completeness and accuracy. This two-pass approach caught gaps:

- **First pass (creation)**: Agent writes a comprehensive knowledge file (e.g., `aws-storage-security.md`, `aws-iam-security.md`)
- **Second pass (review)**: Agent evaluates the file against WAF coverage, comparing structure/depth to existing knowledge files
- **Third pass (remediation)**: Agent fills in identified gaps (e.g., missing Cognito section, underdeveloped resource-based policies, missing shared responsibility model)

### IAM knowledge file review results

The agent reviewed `aws-iam-security.md` against the storage file as a baseline:

| Criteria | Score | Notes |
|----------|-------|-------|
| Completeness | 85/100 | Missing Cognito, IAM Roles Anywhere, expanded resource-based policies |
| Specificity | 95/100 | Excellent policy examples throughout |
| Consistency | 75/100 | Missing cross-service patterns section, shared responsibility section |
| WAF Alignment | 98/100 | Properly grounded in SEC01-SEC04, SEC09 |
| Overall | 88/100 | High-priority gaps identified and queued for remediation |

### Key takeaway

Using a domain-specific agent to review both the bot's responses AND the knowledge files themselves creates a quality loop that's much more rigorous than manual review. The agent catches subtle issues (dropped qualifiers, over-prescriptive language, missing WAF references) that are easy to miss by eye.

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
| 4a        | Strict + IAM file (pre-expansion) | 672 | ~75-80% | Fail (65) |
| 4b        | Strict + IAM file (post-expansion) | 833 | ~70-75% | Fail (45) |

**Note**: Iteration 4 used the same system prompt as iteration 3 but with additional knowledge files loaded. The regression demonstrates that prompt constraints alone are insufficient — the knowledge file size and structure also affect response quality.

---

## Open Questions

- Is there an optimal knowledge file size that balances coverage with grounding quality?
- Should JSON policy examples be removed from knowledge files to prevent synthesis?
- Would a retrieval-augmented approach (search relevant sections, inject only those) outperform full injection?
- Can keyword triggers in the system prompt solve the External ID miss pattern?
- Would reducing `max_tokens` to 500 force more concise, grounded responses?

---

*Last updated: 2026-02-07*
