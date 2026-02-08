import logging
from pathlib import Path

import anthropic
from discord.ext import commands

from bot.rag import KnowledgeStore

logger = logging.getLogger("gen_ai.arch")

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"
KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent / "knowledge"


def _load_base_prompt() -> str:
    return (PROMPTS_DIR / "system.md").read_text()


class Arch(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.client = anthropic.AsyncAnthropic(api_key=bot.anthropic_api_key)
        self.base_prompt = _load_base_prompt()
        self.knowledge = KnowledgeStore(KNOWLEDGE_DIR)
        # Per-user conversation history: {user_id: [{"role": ..., "content": ...}, ...]}
        self.conversations: dict[int, list[dict[str, str]]] = {}

    def _build_system_prompt(self, question: str) -> str:
        results = self.knowledge.query(question, top_k=5)
        context = KnowledgeStore.format_context(results)
        return self.base_prompt + context

    @commands.command()
    async def arch(self, ctx: commands.Context, *, question: str) -> None:
        """Ask the InfoSec Architect a question. DM only."""
        # Ignore anything that isn't a DM
        if ctx.guild is not None:
            return

        # Whitelist check
        if ctx.author.id not in self.bot.whitelisted_users:
            await ctx.send("You are not authorized to use this bot.")
            return

        user_id = ctx.author.id

        # Initialize conversation history for new users
        if user_id not in self.conversations:
            self.conversations[user_id] = []

        self.conversations[user_id].append({"role": "user", "content": question})

        system_prompt = self._build_system_prompt(question)

        logger.info(
            "gen_ai.request",
            extra={
                "gen_ai.system": "anthropic",
                "gen_ai.request.model": "claude-sonnet-4-5-20250929",
                "gen_ai.request.max_tokens": 500,
                "gen_ai.user.id": user_id,
                "gen_ai.user.name": str(ctx.author),
                "gen_ai.prompt.system_length": len(system_prompt),
                "gen_ai.prompt.user": question,
                "gen_ai.prompt.history_length": len(self.conversations[user_id]),
            },
        )

        async with ctx.typing():
            response = await self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=500,
                system=system_prompt,
                messages=self.conversations[user_id],
            )

        assistant_text = response.content[0].text
        self.conversations[user_id].append(
            {"role": "assistant", "content": assistant_text}
        )

        logger.info(
            "gen_ai.response",
            extra={
                "gen_ai.system": "anthropic",
                "gen_ai.response.model": response.model,
                "gen_ai.response.id": response.id,
                "gen_ai.user.id": user_id,
                "gen_ai.usage.input_tokens": response.usage.input_tokens,
                "gen_ai.usage.output_tokens": response.usage.output_tokens,
                "gen_ai.response.finish_reason": response.stop_reason,
                "gen_ai.response.content": assistant_text,
            },
        )

        # Split into chunks that fit Discord's 2000 char limit
        for chunk in _split_message(assistant_text):
            await ctx.send(chunk)

    @commands.command()
    async def clear(self, ctx: commands.Context) -> None:
        """Clear your conversation history. DM only."""
        if ctx.guild is not None:
            return

        if ctx.author.id not in self.bot.whitelisted_users:
            await ctx.send("You are not authorized to use this bot.")
            return

        self.conversations.pop(ctx.author.id, None)
        await ctx.send("Conversation history cleared.")


def _split_message(text: str, limit: int = 2000) -> list[str]:
    """Split a message into chunks that fit within Discord's character limit."""
    if len(text) <= limit:
        return [text]

    chunks: list[str] = []
    while text:
        if len(text) <= limit:
            chunks.append(text)
            break

        # Try to split at a newline
        split_at = text.rfind("\n", 0, limit)
        if split_at == -1:
            # Fall back to splitting at a space
            split_at = text.rfind(" ", 0, limit)
        if split_at == -1:
            # Hard split as last resort
            split_at = limit

        chunks.append(text[:split_at])
        text = text[split_at:].lstrip("\n")

    return chunks


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(Arch(bot))
