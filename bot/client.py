import discord
from discord.ext import commands


class AskAnArchBot(commands.Bot):
    def __init__(
        self,
        anthropic_api_key: str,
        whitelisted_users: set[int],
    ) -> None:
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents)
        self.anthropic_api_key = anthropic_api_key
        self.whitelisted_users = whitelisted_users

    async def setup_hook(self) -> None:
        await self.load_extension("bot.cogs.general")
        await self.load_extension("bot.cogs.arch")

    async def on_ready(self) -> None:
        print(f"Logged in as {self.user} (ID: {self.user.id})")
        print("------")
