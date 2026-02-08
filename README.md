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

After 7 iterations of prompt tuning (documented in [`docs/observations-prompt-tuning.md`](docs/observations-prompt-tuning.md)), the key findings are:

- **Off-topic refusal works perfectly.** The bot reliably refuses questions outside its knowledge scope. Topic boundaries are easy to enforce.
- **On-topic grounding is the hard problem.** The bot consistently supplements knowledge file content with accurate-but-unsourced guidance from its training data. Across 7 iterations, grounding to the knowledge files ranged from ~25-87% depending on question breadth.
- **The elaboration is mostly correct.** WAF compliance scores (~85%) are significantly higher than knowledge grounding scores (~45%). The model draws on the same AWS documentation its knowledge files were written from — so the "fabricated" content is usually accurate, just not from the specified source.
- **Prompt rules hit diminishing returns.** Strict rules, explicit prohibitions, and anti-synthesis instructions improved grounding from ~50% to ~87% for narrow questions, but broad questions still activate training data regardless of constraints.

The core tension: **the bot is a better security advisor than it is a knowledge-file quoter.** Whether that's acceptable depends on the use case. For general Q&A, it's probably fine. For scoring a design against a specific framework, the grounding matters more.

See the full iteration log and findings in [`docs/observations-prompt-tuning.md`](docs/observations-prompt-tuning.md).

## Architecture

```
Discord DM
  |
  v
AskAnArchBot (discord.py)
  |
  v
Claude Sonnet 4.5 API
  |-- System prompt: bot/prompts/system.md (strict rules)
  |-- Knowledge files: bot/knowledge/*.md (WAF Security Pillar content)
  |
  v
Response (constrained to knowledge files)
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
      arch.py                      # InfoSec Architect cog (Claude API)
      general.py                   # General commands
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

- **RAG architecture** — Replace full knowledge injection (~42k input tokens) with retrieval of relevant sections only. Expected to improve grounding and reduce cost.
- **Design review mode** — Accept architecture descriptions or diagrams and return a structured WAF security assessment with a score.
- **More knowledge files** — Expand coverage beyond storage and IAM (networking, compute, detection, incident response).
