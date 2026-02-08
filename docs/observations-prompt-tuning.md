# AskAnArchBot — Prompt Tuning Observations

## Overview

This document captures the iterative process of tuning the bot's system prompt and architecture to constrain responses to loaded knowledge files. The goal: the bot should act as a WAF-constrained security advisor, not a general-purpose AI.

## Test Setup

- **Model**: Claude Sonnet 4.5 (`claude-sonnet-4-5-20250929`)
- **Knowledge files**: `aws-storage-security.md` (567 lines), `aws-iam-security.md` (~3,750 lines)
- **Review agents**: `response-review` (knowledge grounding) + `aws-security-architect` (WAF compliance)
- **Review method**: Dual-agent from iteration 5 onward

---

## Iteration Summary

| Iter | Changes | Test Question | Tokens | Grounding | Grade | WAF |
|------|---------|---------------|--------|-----------|-------|-----|
| 1 | Baseline, no constraints | CMK usage | 2,067 | ~50% | Fail | — |
| 2 | Soft "knowledge-only" instruction | CMK usage | 1,213 | ~55% | Fail | — |
| 3 | Strict rules (verbatim/near-verbatim) | CMK usage | 415 | ~87% | B+ | — |
| 4a | + IAM file (pre-expansion) | S3 third-party policy | 672 | ~75% | Fail (65) | — |
| 4b | + IAM file (post-expansion) | S3 third-party policy | 833 | ~70% | Fail (45) | — |
| 5 | Unchanged (dual-agent review) | Federation via IdP | 1,105 | ~30% | Fail (30) | ~75% |
| 6 | + Rule 6 (JSON anti-synthesis) | Federation via IdP | 865 | ~25% | Fail (28) | ~80% |
| 7 | + Knowledge gap fill + max_tokens=500 | S3 standards + wildcards | 500 | ~45% | Fail (32) | ~85% |

---

## Key Findings

### What worked

1. **Explicit prohibitions outperform positive instructions.** "Do not generate checklists" beats "keep responses concise." The model needs to know what NOT to do.

2. **"Verbatim or near-verbatim" is the most effective constraint phrase.** Iteration 3 achieved ~87% grounding with this language — the best result across all iterations.

3. **Off-topic refusal is easy.** A single clear instruction with an exact refusal message worked from the first attempt. The hard problem is constraining on-topic responses.

4. **Strict rules eliminated the worst fabrication patterns.** Fabricated checklists, "common mistakes" sections, and CLI commands were successfully suppressed by iterations 3+.

5. **Filling knowledge gaps reduces fabrication targets.** Adding SAML trust policy examples (iteration 7) gives the bot verbatim material to quote instead of fabricating.

### What didn't work

6. **Prompt rules alone cannot prevent training data leakage.** Across 7 iterations of increasingly strict rules, grounding never reliably exceeded ~45% for broad questions. The model draws on training data whenever the knowledge file doesn't provide enough material for a complete answer.

7. **More knowledge = more synthesis, not more grounding.** Adding the 3,683-line IAM file (iteration 4) gave the model more raw material to synthesize from, which increased verbosity and reduced grounding.

8. **Anti-synthesis rules reduce volume but not fabrication ratio.** Rule 6 cut JSON blocks from 6 to 4, but ~75% of JSON blocks were still fabricated. The model doesn't evaluate whether an example exists before generating it.

9. **`max_tokens` is a blunt instrument.** Hard-capping at 500 (iteration 7) causes mid-sentence truncation, missing closing lines, and incomplete JSON. The model doesn't know its budget so it can't prioritize.

### Patterns discovered

10. **WAF compliance != knowledge grounding.** A response can be ~85% WAF-compliant but only ~45% grounded in the knowledge files. The model supplements with accurate WAF knowledge from training data — the elaboration is mostly correct, just not from the knowledge files specifically.

11. **Missing knowledge = fabrication magnet.** The bot fabricates exactly where the knowledge files have conceptual mentions but no concrete examples. When an example exists (GitHub OIDC), it gets quoted. When it doesn't (SAML), the model invents one.

12. **Token count correlates with compliance** — but only up to a point. Unconstrained: 2,067 tokens (~50% grounded). Strict: 415 tokens (~87% grounded). But broader questions break this pattern regardless of token count.

---

## Current System Prompt Rules

1. **Knowledge-only responses** — verbatim or near-verbatim from Reference Knowledge
2. **Off-topic refusal** — exact message, nothing else
3. **Be brief** — no exhaustive guides, fabricated sections
4. **Closing line** — required on every response
5. **No fabrication** — no CLI commands, IAM lists, procedures, "common mistakes"
6. **JSON anti-synthesis** — quote complete examples only, never combine/merge/modify

---

## Review Workflow

### Dual-agent review process

1. Bot responds to test question
2. Launch `response-review` agent — evaluates knowledge grounding, rule compliance, token efficiency
3. Launch `aws-security-architect` agent — evaluates WAF alignment, missing security principles
4. Both return concise reports (~200-300 tokens each)

| Agent | Focus | Catches |
|-------|-------|---------|
| `response-review` | Knowledge grounding, rule compliance | Fabricated content, missing references, rule violations |
| `aws-security-architect` | WAF alignment, security completeness | Non-WAF guidance, missing best practices, incorrect citations |

### Agent-assisted knowledge file creation

Used the `aws-security-architect` agent in a three-pass workflow:
1. **Create**: Agent writes comprehensive knowledge file
2. **Review**: Agent evaluates against WAF coverage
3. **Remediate**: Agent fills identified gaps

---

## Decision: Accept Elaboration (Option A)

After 7 iterations, we've determined that **prompt-level constraints alone cannot fully prevent training data elaboration**. This is a fundamental LLM behavior, not a prompt engineering failure.

**What the knowledge files actually do well:**
- Define topic boundaries (off-topic refusal works perfectly)
- Provide verbatim examples the bot can quote (when they exist)
- Set the WAF-grounded tone and structure

**What they can't do:**
- Prevent the model from supplementing with accurate training data on covered topics
- Force strict quotation when the knowledge file only mentions a concept briefly

**Accepted trade-off**: The bot produces WAF-compliant guidance (~85%) that draws partially from training data beyond the knowledge files (~45% grounded). The elaboration is mostly accurate — it's AWS WAF knowledge from the same source material the knowledge files were written from.

---

## Recommended Next Step: RAG Architecture (Option B)

The current architecture injects all knowledge files (~4,250 lines, ~42,000 input tokens) into every system prompt. This is expensive, slow, and gives the model too much material to synthesize from.

**Proposed change**: Retrieval-Augmented Generation (RAG)
1. Embed knowledge file sections into a vector store
2. On each user question, retrieve only the top 3-5 most relevant sections (~50-100 lines)
3. Inject only those sections into the system prompt
4. Smaller, more focused context = less training data activation, better grounding

**Expected benefits**:
- Lower input token cost (~5,000 vs ~42,000 per request)
- Better grounding (less material to synthesize from — mirrors the iteration 3 result where a single focused knowledge file achieved ~87%)
- Faster response times
- Scales to more knowledge files without linear cost increase

**Trade-offs**:
- Retrieval quality becomes a new failure mode (wrong sections retrieved)
- More infrastructure (vector store, embedding pipeline)
- Need to evaluate chunking strategy for knowledge files

---

## Open Items

- [ ] Implement RAG architecture (Option B) when ready to invest
- [ ] Re-test federation question to verify SAML examples get quoted from updated knowledge file
- [ ] Evaluate whether `max_tokens` should be increased to 600-700 to avoid mid-sentence truncation
- [ ] Consider adding system prompt instruction for self-regulated length ("keep under 400 tokens") instead of hard cap
- [ ] Test with different models (Haiku for faster/cheaper, Opus for better instruction following)
- [ ] Rate limiting before production use

---

*Last updated: 2026-02-07*
