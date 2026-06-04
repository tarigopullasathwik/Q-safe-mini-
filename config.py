"""Application configuration for Q-SAFE Nexus."""

import os
import secrets
import warnings
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
DATABASE_PATH = BASE_DIR / "qsafe_nexus.db"
TRANSFER_FOLDER = BASE_DIR / "uploads" / "transferred"


def _resolve_secret_key() -> str:
    """Return the Flask secret key from the environment.

    In production the QSAFE_SECRET_KEY environment variable must be set to a
    strong random value.  During local development a random ephemeral key is
    generated automatically and a warning is emitted so the gap is visible in
    the console without crashing the dev server.
    """
    key = os.environ.get("QSAFE_SECRET_KEY", "")
    if key:
        return key

    # Allow an optional .env-style variable for local convenience.
    env_file = BASE_DIR / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("QSAFE_SECRET_KEY="):
                key = line.split("=", 1)[1].strip().strip("\"'")
                if key:
                    return key

    # Fail hard in production; survive gracefully in development.
    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError(
            "QSAFE_SECRET_KEY environment variable must be set in production."
        )

    ephemeral = secrets.token_hex(32)
    warnings.warn(
        "QSAFE_SECRET_KEY is not set. Using a random ephemeral key — "
        "sessions will be lost on restart. Set the variable in .env for "
        "persistent local development.",
        stacklevel=2,
    )
    return ephemeral


class Config:
    """Base Flask configuration."""

    # HIGH-1 FIX: no hard-coded fallback; ephemeral key with warning in dev.
    SECRET_KEY = _resolve_secret_key()
    UPLOAD_FOLDER = str(UPLOAD_FOLDER)
    DATABASE_PATH = str(DATABASE_PATH)
    TRANSFER_FOLDER = str(TRANSFER_FOLDER)
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
