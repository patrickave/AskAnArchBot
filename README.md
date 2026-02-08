# AskAnArchBot

A Discord bot that acts as a knowledge-constrained InfoSec Architect, built to explore a real question: **can a local AI agent reliably review security architecture designs without fabricating guidance?**

## The Problem

Solutions Architects design systems, then hand those designs to Security Architects for review. That review process is slow, bottlenecked by availability, and often inconsistent across reviewers. The idea behind AskAnArchBot is simple — what if an architect could pass their design to a bot and get an immediate security assessment grounded in the AWS Well-Architected Framework?

But there's a catch. If the bot fabricates security recommendations, it's worse than no bot at all. Bad security advice delivered with confidence is dangerous. So before building the design-review feature, we needed to answer a harder question first: **can we actually constrain an LLM to only say what's in its knowledge base?**

## What This Project Is

This is an R&D testbed, not a production tool. We're iterating on prompt engineering, knowledge file design, and review workflows to understand the boundaries of LLM knowledge grounding.

**Current phase**: General Q&A against security knowledge files. Users ask the bot security questions via Discord DM, and the bot responds using only its loaded knowledge files (AWS WAF Security Pillar content). We then review every response with automated agents to measure how much the bot fabricates vs. grounds in source material.

**Target phase**: Architecture design review. A Solutions Architect uploads or describes their design, and the bot evaluates it against WAF best practices — returning a security score, identifying gaps, and recommending specific controls. All grounded in the knowledge base, not the model's training data.

## What We've Learned So Far

After 8 iterations of prompt tuning and architecture changes (documented in [`docs/observations-prompt-tuning.md`](docs/observations-prompt-tuning.md)), the key findings are:

- **Off-topic refusal works perfectly.** The bot reliably refuses questions outside its knowledge scope. Topic boundaries are easy to enforce.
- **On-topic grounding is the hard problem.** The bot consistently supplements knowledge file content with accurate-but-unsourced guidance from its training data. Across 7 iterations of prompt tuning, grounding ranged from ~25-87% depending on question breadth.
- **RAG dramatically reduces cost but exposes retrieval quality as the new bottleneck.** Iteration 8 replaced full knowledge injection (~42k input tokens) with TF-IDF retrieval (~6k input tokens — 86% reduction). Cost per request dropped from ~$0.13 to ~$0.02. However, cross-domain questions (spanning IAM + S3) retrieve only IAM chunks, missing verbatim S3 policy examples — dropping grounding from ~75% to ~40%.
- **Prompt rules hit diminishing returns.** Strict rules improved grounding from ~50% to ~87% for narrow questions, but broad questions still activate training data. RAG addresses cost architecturally but retrieval quality must improve before grounding can match the full-injection baseline.

The core tension: **cost vs. retrieval quality.** Full knowledge injection is expensive but grounded (~75%). RAG is cheap but misses cross-domain content (~40%). The next lever is smarter retrieval, not more prompt engineering. See the full iteration log in [`docs/observations-prompt-tuning.md`](docs/observations-prompt-tuning.md).

## Architecture

```
Discord DM
  |
  v
AskAnArchBot (discord.py)
  |
  v
RAG Retrieval (TF-IDF, top-5 chunks)
  |-- Chunks: bot/knowledge/*.md split at H2/H3 headers (~48 chunks)
  |-- Index: scikit-learn TfidfVectorizer (in-memory, built at startup)
  |
  v
Claude Sonnet 4.5 API
  |-- System prompt: bot/prompts/system.md (strict rules)
  |-- Retrieved knowledge: top-5 relevant chunks (~2-6k tokens)
  |
  v
Response (constrained to retrieved knowledge)
```

**Review pipeline** (development only):
```
Bot response
  |
  +--> response-review agent (knowledge grounding, rule compliance)
  +--> aws-security-architect agent (WAF alignment, missing controls)
  |
  v
Dual-agent report (grounding %, WAF compliance, fabrication list)
```

## Project Structure

```
AskAnArchBot/
  main.py                          # Entry point
  bot/
    client.py                      # Discord bot client
    cogs/
      arch.py                      # InfoSec Architect cog (Claude API + RAG)
      general.py                   # General commands
    rag/
      __init__.py                  # Package exports
      chunker.py                   # Markdown chunking (H2/H3 splitting)
      retriever.py                 # TF-IDF index and cosine similarity retrieval
    prompts/
      system.md                    # System prompt with strict rules
    knowledge/
      aws-storage-security.md      # S3, EBS, EFS security (WAF-aligned)
      aws-iam-security.md          # IAM, STS, federation security (WAF-aligned)
  docs/
    observations-prompt-tuning.md  # Iteration log and findings
  .claude/
    agents/
      response-review.md           # Automated response grading agent
      aws-security-architect.md    # WAF compliance review agent
```

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
# Add DISCORD_TOKEN, ANTHROPIC_API_KEY, WHITELISTED_USERS to .env
python3 main.py
```

DM the bot with `!arch <question>` to ask a security question. Use `!clear` to reset conversation history.

## Next Steps

- **Fix cross-domain retrieval** — TF-IDF misses S3 storage chunks when questions also mention IAM. Options: keyword boosting for domain terms, hybrid retrieval, or upgrade to sentence-transformers embeddings.
- **Increase max_tokens** — 500 is too low for security responses with JSON examples. Two truncations in iteration 8.
- **Design review mode** — Accept architecture descriptions or diagrams and return a structured WAF security assessment with a score.
- **More knowledge files** — Expand coverage beyond storage and IAM (networking, compute, detection, incident response).
