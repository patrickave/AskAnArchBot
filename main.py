import os

from dotenv import load_dotenv

from bot.client import AskAnArchBot


def main() -> None:
    load_dotenv()
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        raise SystemExit("DISCORD_TOKEN environment variable is not set. See .env.example")

    bot = AskAnArchBot()
    bot.run(token)


if __name__ == "__main__":
    main()
