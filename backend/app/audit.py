"""Structured, allow-listed security event logging."""

import json
import logging
import sys
from datetime import UTC, datetime

logger = logging.getLogger("docvault.security")
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


def record_security_event(
    event: str,
    outcome: str,
    *,
    actor_id: str | None = None,
    target_id: str | None = None,
    source_ip: str | None = None,
    reason: str | None = None,
) -> None:
    """Emit only bounded, explicitly selected fields; never pass request bodies."""
    safe_event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event": event,
        "outcome": outcome,
        "actor_id": actor_id,
        "target_id": target_id,
        "source_ip": source_ip[:64] if source_ip else None,
        "reason": reason,
    }
    logger.info("%s", json.dumps(safe_event, separators=(",", ":"), sort_keys=True))
