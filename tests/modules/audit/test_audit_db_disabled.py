import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.modules.audit.enum import LogSeverity
from src.modules.audit.schemas import LogEvent
from src.modules.audit.service import log_event
from src.settings import settings


async def test_audit_logging_with_db_disabled(
    db_session: AsyncSession,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Verifies that audit logging executes without crashing when DB persistence is disabled."""
    # 1. Point log directory to temporary test folder
    monkeypatch.setattr(settings, "log_dir", str(tmp_path))
    monkeypatch.setattr(settings, "log_to_db", False)
    monkeypatch.setattr(settings, "log_to_file", True)

    event = LogEvent(
        event_type="SYSTEM_FILE_ONLY_TEST",
        severity=LogSeverity.INFO,
        message="Testing file-only audit logging execution.",
        user_id="test-worker",
        request_id="req-file-only-123",
    )

    # 2. Invoke maestro
    response = await log_event(event=event, session=db_session)

    # 3. Assert response structure
    assert response.id is None
    assert response.event_type == "SYSTEM_FILE_ONLY_TEST"
    assert response.message == "Testing file-only audit logging execution."
    assert isinstance(response.created_at, datetime)

    # Allow background thread file writer to complete
    await asyncio.sleep(0.3)

    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    json_file = tmp_path / f"{date_str}.json"
    assert json_file.exists()

    # 4. Verify NDJSON compliance (must be single physical line per record)
    with open(json_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    assert len(lines) >= 1
    # Each line must be a valid self-contained JSON object
    last_record = json.loads(lines[-1])
    assert last_record["event_type"] == "SYSTEM_FILE_ONLY_TEST"
    assert last_record["id"] is None
