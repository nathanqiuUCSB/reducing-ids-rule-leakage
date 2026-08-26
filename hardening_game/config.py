"""Environment configuration shared by mutation commands."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_project_env(env_path: Path | None = None) -> None:
    """Load an ignored project .env without overriding shell values."""
    load_dotenv(env_path or PROJECT_ROOT / ".env", override=False)


def configured_litellm_base_url() -> str | None:
    """Return the explicitly configured OpenAI-compatible API base URL."""
    value = os.environ.get("LITELLM_BASE_URL", "").strip()
    return value or None
