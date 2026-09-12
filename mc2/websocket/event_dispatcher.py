"""
Event dispatcher — subscribes to Redis pub/sub and routes events to WebSocket clients.

Redis channels:
  frothiq:cc:ENVELOPE_UPDATE
  frothiq:cc:DEFENSE_CLUSTER_UPDATE
  frothiq:cc:LICENSE_REVOKED
  frothiq:cc:ORCHESTRATION_DECISION
  frothiq:cc:FLYWHEEL_SIGNAL
  frothiq:cc:AUDIT_ACTION       ← internal Control Center events
  frothiq:cc:SIMULATION_RESULT

Each channel maps to a minimum role required to receive the event.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from .connection_manager import connection_manager

logger = logging.getLogger(__name__)

# channel_suffix → minimum_role
CHANNEL_ROLE_MAP: dict[str, str] = {
    "ENVELOPE_UPDATE": "security_analyst",
    "DEFENSE_CLUSTER_UPDATE": "security_analyst",
    "LICENSE_REVOKED": "super_admin",
    "ORCHESTRATION_DECISION": "security_analyst",
    "FLYWHEEL_SIGNAL": "security_analyst",
    "AUDIT_ACTION": "security_analyst",
    "SIMULATION_RESULT": "security_analyst",
    "SYSTEM_ALERT": "read_only",
    "THREAT_LEVEL_CHANGE": "read_only",
}

CHANNEL_PREFIX = "frothiq:cc:"


async def start_event_dispatcher(redis_pubsub_client) -> None:
    """
    Start the Redis pub/sub subscriber loop.
    Should be called once at application startup in a background task.
    """
    channels = [f"{CHANNEL_PREFIX}{suffix}" for suffix in CHANNEL_ROLE_MAP]

    try:
        pubsub = redis_pubsub_client.pubsub()
        await pubsub.subscribe(*channels)
        logger.info("Event dispatcher subscribed to %d channels", len(channels))

        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            await _handle_message(message)

    except asyncio.CancelledError:
        logger.info("Event dispatcher cancelled")
        raise
    except Exception as exc:
        logger.error("Event dispatcher error: %s", exc, exc_info=True)
        raise


async def _handle_message(message: dict[str, Any]) -> None:
    """Process an incoming Redis pub/sub message and dispatch to WebSocket clients."""
    # Redis reports subscribe/unsubscribe confirmations on the same stream as
    # real traffic, with the subscription COUNT in `data` rather than a payload.
    # Without this guard each confirmation was decoded as an event and
    # broadcast to every connected client — a spurious event on the wire each
    # time the dispatcher (re)subscribed.
    if message.get("type") not in ("message", "pmessage"):
        return

    channel = message.get("channel", b"").decode("utf-8")
    data_raw = message.get("data", b"")

    # Derive event_type from channel suffix
    event_type = channel.removeprefix(CHANNEL_PREFIX)
    min_role = CHANNEL_ROLE_MAP.get(event_type, "super_admin")

    try:
        payload = json.loads(data_raw)
    except (json.JSONDecodeError, TypeError):
        payload = {"raw": data_raw.decode("utf-8", errors="replace") if isinstance(data_raw, bytes) else str(data_raw)}

    tenant_id = payload.pop("tenant_id", None) if isinstance(payload, dict) else None

    sent = await connection_manager.broadcast(
        event_type=event_type,
        payload=payload,
        min_role=min_role,
        tenant_id=tenant_id,
    )

    if sent > 0:
        logger.debug("Dispatched %s to %d clients", event_type, sent)


async def publish_event(
    redis_client,
    event_type: str,
    payload: dict[str, Any],
    tenant_id: str | None = None,
) -> None:
    """
    Publish an event to the Redis channel so all Control Center instances receive it.
    Can also be called directly to push events without going through Redis
    (e.g. from audit logging on the same instance).
    """
    if tenant_id:
        payload["tenant_id"] = tenant_id

    channel = f"{CHANNEL_PREFIX}{event_type}"
    try:
        await redis_client.publish(channel, json.dumps(payload))
    except Exception as exc:
        logger.error("Failed to publish event %s: %s", event_type, exc)
        # Fall back to direct broadcast on same instance
        await connection_manager.broadcast(
            event_type=event_type,
            payload=payload,
            min_role=CHANNEL_ROLE_MAP.get(event_type, "super_admin"),
        )
