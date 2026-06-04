"""Shared pytest fixtures for Q-SAFE Nexus tests."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def isolated_db(monkeypatch: pytest.MonkeyPatch) -> Path:
    """Use a temporary SQLite file so transfer tests do not touch production data."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as handle:
        db_path = Path(handle.name)

    monkeypatch.setattr("services.database.DATABASE_PATH", db_path)
    yield db_path
    db_path.unlink(missing_ok=True)


@pytest.fixture
def aes_key() -> bytes:
    """256-bit AES key for encryption round-trip tests."""
    from encryption.aes import generate_key

    return generate_key()
