# AskAnArchBot — Prompt Tuning Observations

## Overview

This document captures the iterative process of tuning the bot's system prompt and architecture to constrain responses to loaded knowledge files. The goal: the bot should act as a WAF-constrained security advisor, not a general-purpose AI.

## Test Setup

- **Model**: Claude Sonnet 4.5 (`claude-sonnet-4-5-20250929`)
- **Knowledge files**: `aws-storage-security.md` (567 lines), `aws-iam-security.md` (~3,750 lines)
- **Retrieval**: TF-IDF RAG from iteration 8 onward (scikit-learn, in-memory, top-k retrieval)
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
| 8a | RAG (TF-IDF, top_k=3) | S3 standards + wildcards | 458 | ~50% | Pending | Pending |
| 8b | RAG (TF-IDF, top_k=5) | S3 third-party conditional policy | 500 | ~40% | Fail (22) | ~65% |

---

## Iteration 8 — RAG Architecture

### 8a: TF-IDF with top_k=3

**Change**: Replaced full knowledge injection (~42k input tokens) with TF-IDF retrieval. On each question, the bot retrieves the top-3 most relevant knowledge chunks and injects only those into the system prompt. Uses scikit-learn TfidfVectorizer (english stop words, unigram+bigram, max_df=0.9, sublinear TF) with cosine similarity ranking and a 6,000-token budget cap.

**Infrastructure**: 48 chunks from 2 knowledge files, 10,820 vocab terms, in-memory index built at startup in <1s. No vector DB — the TF-IDF matrix fits in a few KB.

**Test question**: "what are the security standards for S3 and is it wrong if i build a s3 iam policy with * in it?"

**Results**:
- Input tokens: **6,548** (down from 42,651 — **85% reduction**)
- Output tokens: **458** (completed naturally with `end_turn`, no truncation)
- Response acknowledged it lacked S3-specific content and grounded guidance in retrieved IAM chunks
- Retrieved chunks: Permission Boundaries, Cognito Identity Pools, Cross-Service IAM Patterns
- Retrieval gap: S3-specific chunks (`aws-storage-security > Amazon S3 Security`) not retrieved because "IAM policy" keywords dominated over "S3 security standards"

**Observations**:
- Token cost reduction is dramatic and matches expectations from the plan (~85-95% reduction)
- The model was more honest about knowledge gaps — instead of fabricating S3 content, it said "I cannot give you comprehensive guidance on S3-specific security standards, as that content is not included in the sections I have access to"
- Retrieval quality is now the primary bottleneck, not prompt engineering
- top_k=3 is too narrow for cross-domain questions that span both IAM and storage knowledge

### 8b: Bump to top_k=5

**Change**: Increased retrieval from top-3 to top-5 chunks. Wider retrieval window should capture cross-domain content (e.g., S3 security chunks alongside IAM policy chunks for questions that span both).

**Test question**: "make a IAM recommendation for a conditional policy for a s3 bucket for a third party to access, i have their organizationID and role."

**Retrieved chunks** (all from IAM file — no S3 storage chunks retrieved):

| Rank | Chunk | Score | Relevant? |
|------|-------|-------|-----------|
| 1 | IAM Users, Groups, and Roles | 0.0775 | Partial |
| 2 | When Access Keys are Unavoidable | 0.0681 | No |
| 3 | IAM Access Analyzer (SEC04-BP03) | 0.0681 | Partial |
| 4 | IAM Roles for Cross-Account Access (SEC03-BP05) | 0.0591 | Yes |
| 5 | Lambda Execution Roles (SEC02-BP03) | 0.0587 | No |

**Results**:
- Input tokens: **6,007** (down from 42,651 — **86% reduction**)
- Output tokens: **500** (truncated at max_tokens)
- Finish reason: `max_tokens` — response cut off mid-JSON, missing closing line

**Dual-agent review**:

| Agent | Score | Key Findings |
|-------|-------|-------------|
| response-review | **22/100** (grounding ~40%) | JSON policy synthesized, not quoted verbatim. Knowledge file has exact cross-account S3 bucket policy example (line ~2392) with `aws:PrincipalOrgID` but retriever didn't pull it. Editorial sections fabricated. Missing closing line (truncated). |
| aws-security-architect | **~65% WAF** (2/7 principles) | Confuses S3 bucket policy vs IAM role trust policy (External ID mentioned in wrong context). Missing encryption (SSE-KMS), secure transport (`aws:SecureTransport`), logging (CloudTrail data events). Truncation broke response mid-JSON. |

**Observations**:
- **top_k=5 did not fix the cross-domain retrieval gap.** All 5 retrieved chunks came from `aws-iam-security.md`. The `aws-storage-security > Amazon S3 Security` section — which contains the exact verbatim bucket policy examples for this question (`aws:PrincipalOrgID`, `aws:SecureTransport` deny, SSE-KMS enforcement) — was not retrieved.
- **TF-IDF keyword bias**: The question contains "IAM", "policy", "conditional", "role" which all have high TF-IDF weight in the IAM file. "S3 bucket" appears in both files but the IAM-heavy bigrams dominate scoring. This is a fundamental TF-IDF limitation for cross-domain queries.
- **Grounding dropped vs baseline.** Iteration 4a tested the same question type with full knowledge injection and scored ~75% grounding. RAG 8b scored ~40%. The retriever is actively harming grounding by excluding the most relevant content.
- **WAF compliance also dropped.** From ~85% (iter 7) to ~65%. Without the S3 security chunks, the bot can't recommend encryption, secure transport, or logging — all critical WAF controls that exist verbatim in the knowledge files.
- **max_tokens=500 still truncates.** The response was cut mid-JSON for the second time. This remains an unresolved issue from iteration 7.

**Conclusion**: RAG delivers massive cost savings (86% token reduction) but retrieval quality is now the dominant failure mode. The TF-IDF retriever needs domain-aware improvements (keyword boosting, cross-file retrieval) before grounding can improve beyond the full-injection baseline.

---

## Key Findings

### What worked

1. **Explicit prohibitions outperform positive instructions.** "Do not generate checklists" beats "keep responses concise." The model needs to know what NOT to do.

2. **"Verbatim or near-verbatim" is the most effective constraint phrase.** Iteration 3 achieved ~87% grounding with this language — the best result across all iterations.

3. **Off-topic refusal is easy.** A single clear instruction with an exact refusal message worked from the first attempt. The hard problem is constraining on-topic responses.

4. **Strict rules eliminated the worst fabrication patterns.** Fabricated checklists, "common mistakes" sections, and CLI commands were successfully suppressed by iterations 3+.

5. **Filling knowledge gaps reduces fabrication targets.** Adding SAML trust policy examples (iteration 7) gives the bot verbatim material to quote instead of fabricating.

6. **RAG makes the model more honest about gaps.** With only relevant chunks injected (iteration 8a), the model explicitly acknowledged missing S3 content rather than fabricating from training data. Smaller context = less material to synthesize from = more grounding.

7. **RAG cost savings are real and dramatic.** Input tokens dropped 85-86% (42k → 6k) with no infrastructure complexity — in-memory TF-IDF index built at startup in <1s.

### What didn't work

8. **Prompt rules alone cannot prevent training data leakage.** Across 7 iterations of increasingly strict rules, grounding never reliably exceeded ~45% for broad questions. The model draws on training data whenever the knowledge file doesn't provide enough material for a complete answer.

9. **More knowledge = more synthesis, not more grounding.** Adding the 3,683-line IAM file (iteration 4) gave the model more raw material to synthesize from, which increased verbosity and reduced grounding.

10. **Anti-synthesis rules reduce volume but not fabrication ratio.** Rule 6 cut JSON blocks from 6 to 4, but ~75% of JSON blocks were still fabricated. The model doesn't evaluate whether an example exists before generating it.

11. **`max_tokens` is a blunt instrument.** Hard-capping at 500 (iteration 7) causes mid-sentence truncation, missing closing lines, and incomplete JSON. The model doesn't know its budget so it can't prioritize.

### Patterns discovered

12. **TF-IDF has a cross-domain retrieval blind spot.** For questions spanning both IAM and S3 storage, the retriever pulls exclusively from the IAM file because keyword overlap is higher. The S3-specific chunks with verbatim policy examples are never retrieved, even at top_k=5. This actively harms grounding — iteration 8b scored ~40% vs ~75% for the same question type with full injection (iteration 4a).

13. **WAF compliance != knowledge grounding.** A response can be ~85% WAF-compliant but only ~45% grounded in the knowledge files. The model supplements with accurate WAF knowledge from training data — the elaboration is mostly correct, just not from the knowledge files specifically.

14. **Missing knowledge = fabrication magnet.** The bot fabricates exactly where the knowledge files have conceptual mentions but no concrete examples. When an example exists (GitHub OIDC), it gets quoted. When it doesn't (SAML), the model invents one.

15. **Token count correlates with compliance** — but only up to a point. Unconstrained: 2,067 tokens (~50% grounded). Strict: 415 tokens (~87% grounded). But broader questions break this pattern regardless of token count.

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

## Decision: RAG Architecture (Implemented)

After 7 iterations of prompt tuning, we determined that prompt-level constraints alone cannot fully prevent training data elaboration. RAG was implemented in iteration 8 to address this architecturally.

**What RAG delivered**:
- Input token cost: **~42k → ~6k per request (85-86% reduction)**
- Model honesty: with smaller context, the model acknowledges gaps instead of fabricating (iteration 8a)
- Off-topic refusal still works perfectly with RAG

**What RAG exposed**:
- **Retrieval quality is the new bottleneck.** TF-IDF keyword matching has a cross-domain blind spot — questions spanning IAM + S3 retrieve only IAM chunks, missing verbatim S3 policy examples
- **Grounding dropped for cross-domain questions.** Iteration 8b scored ~40% grounding vs ~75% for the same question with full injection (iteration 4a). The retriever is excluding the most relevant content.
- **WAF compliance also dropped.** From ~85% (iter 7) to ~65% (iter 8b). Without S3 security chunks, the bot can't recommend encryption, secure transport, or logging.

**Current trade-off**: RAG saves ~86% on cost but retrieval quality must improve before grounding can match or exceed the full-injection baseline. The next lever is retrieval — not prompt engineering.

---

## Open Items

- [x] Implement RAG architecture — done in iteration 8 (TF-IDF, scikit-learn, in-memory)
- [x] Run dual-agent review on iteration 8b (top_k=5) — grounding ~40%, WAF ~65%
- [ ] Fix cross-domain retrieval: S3 storage chunks not retrieved for questions mentioning both IAM and S3. Options: keyword boosting, hybrid retrieval, or embedding-based retrieval (sentence-transformers)
- [ ] Re-test federation question with RAG to verify SAML examples get retrieved and quoted
- [ ] Increase max_tokens above 500 — two consecutive truncations (8a: natural end, 8b: truncated). Security responses with JSON examples need ~800-1500 tokens
- [ ] Test with different models (Haiku for faster/cheaper, Opus for better instruction following)
- [ ] Rate limiting before production use

---

*Last updated: 2026-02-07*
