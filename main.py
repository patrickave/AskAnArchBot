import json
import logging
import os

from dotenv import load_dotenv

from bot.client import AskAnArchBot


class OTelJsonFormatter(logging.Formatter):
    """Structured JSON formatter using OTel semantic conventions."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": self.formatTime(record),
            "severity": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }
        # Pull all gen_ai.* attributes from the extra dict
        for key, value in record.__dict__.items():
            if key.startswith("gen_ai."):
                entry[key] = value
        return json.dumps(entry, indent=2, default=str)


def _configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(OTelJsonFormatter())

    gen_ai_logger = logging.getLogger("gen_ai")
    gen_ai_logger.setLevel(logging.DEBUG)
    gen_ai_logger.addHandler(handler)


def main() -> None:
    load_dotenv()
    _configure_logging()
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        raise SystemExit("DISCORD_TOKEN environment variable is not set. See .env.example")

    anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
    if not anthropic_api_key:
        raise SystemExit("ANTHROPIC_API_KEY environment variable is not set. See .env.example")

    raw_whitelist = os.getenv("WHITELISTED_USERS", "")
    whitelisted_users = {
        int(uid.strip())
        for uid in raw_whitelist.split(",")
        if uid.strip()
    }

    bot = AskAnArchBot(
        anthropic_api_key=anthropic_api_key,
        whitelisted_users=whitelisted_users,
    )
    bot.run(token)


if __name__ == "__main__":
    main()
