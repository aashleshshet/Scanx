"""Apply the additive v1 schema: python -m api_sentry.platform.migrate."""

import os

from .database import Store

if __name__ == "__main__":
    Store(os.environ.get("DATABASE_URL", "sqlite:///onescanx.db")).migrate()
    print("OnescanX schema v1 ready")
