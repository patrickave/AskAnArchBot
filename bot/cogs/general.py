import discord
from discord.ext import commands


class General(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @commands.command()
    async def ping(self, ctx: commands.Context) -> None:
        """Check if the bot is alive."""
        latency_ms = round(self.bot.latency * 1000)
        await ctx.send(f"Pong! ({latency_ms}ms)")

    @commands.command()
    async def hello(self, ctx: commands.Context) -> None:
        """Say hello."""
        await ctx.send(f"Hey {ctx.author.display_name}!")


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(General(bot))
