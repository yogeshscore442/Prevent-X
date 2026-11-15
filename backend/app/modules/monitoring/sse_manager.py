"""
PREVENT-X Server-Sent Events (SSE) & Redis Pub/Sub Dispatcher (MOD-09, MOD-12)
Provides real-time streaming of security telemetry to connected dashboards
with tenant isolation, reconnection replay (Last-Event-ID), and heartbeat keepalives.
"""

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Generator, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.integrations.redis_client import get_redis_client
from backend.app.models.monitoring import SecurityEvent

logger = logging.getLogger("preventx.monitoring.sse")

HEARTBEAT_INTERVAL_SECONDS = 15.0
POLL_TIMEOUT_SECONDS = 1.0


def format_sse(event_type: str, data: Any, event_id: Optional[str] = None) -> str:
    """
    Formats a message adhering to the W3C Server-Sent Events standard.
    """
    buffer = []
    if event_id:
        buffer.append(f"id: {event_id}\n")
    buffer.append(f"event: {event_type}\n")
    payload = json.dumps(data, default=str) if not isinstance(data, str) else data
    buffer.append(f"data: {payload}\n\n")
    return "".join(buffer)


class SSEManager:
    """
    Manages tenant-scoped real-time event broadcasting and client streaming.
    """

    @staticmethod
    def format_sse_message(event_name: str, data: Any, event_id: Optional[str] = None) -> str:
        """
        Formats a message adhering to the W3C Server-Sent Events standard.
        """
        return format_sse(event_type=event_name, data=data, event_id=event_id)

    @classmethod
    def publish_event(cls, organization_id: uuid.UUID, event_dict: Dict[str, Any]) -> bool:
        """
        Publishes a normalized security event to the organization's Redis channel.
        """
        channel = f"preventx:events:{organization_id}"
        client = get_redis_client()
        if client is None:
            logger.debug("Redis client unavailable; skipped pubsub broadcast for %s", channel)
            return False

        try:
            payload = json.dumps(event_dict, default=str)
            client.publish(channel, payload)
            logger.debug("Published event to %s: %s", channel, event_dict.get("id"))
            return True
        except Exception as exc:
            logger.warning("Failed to publish event to Redis channel %s: %s", channel, exc)
            return False

    @classmethod
    def event_stream_generator(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        last_event_id: Optional[str] = None,
        max_duration_seconds: float = 300.0,
        heartbeat_interval: float = 15.0,
    ) -> Generator[str, None, None]:
        """
        Yields Server-Sent Events for the active tenant:
        1. Replays missed events if last_event_id is provided.
        2. Streams real-time events via Redis Pub/Sub.
        3. Sends periodic keep-alive comments.
        """
        # Yield initial connection confirmation
        yield format_sse("connected", {"status": "CONNECTED", "organization_id": str(organization_id)})

        # 1. Replay missed events if client reconnected with Last-Event-ID
        if last_event_id:
            try:
                last_uuid = uuid.UUID(last_event_id.strip())
                last_event = db.scalar(
                    select(SecurityEvent).where(
                        SecurityEvent.id == last_uuid,
                        SecurityEvent.organization_id == organization_id,
                    )
                )
                if last_event:
                    missed_events = list(
                        db.scalars(
                            select(SecurityEvent)
                            .where(
                                SecurityEvent.organization_id == organization_id,
                                SecurityEvent.timestamp > last_event.timestamp,
                            )
                            .order_by(SecurityEvent.timestamp.asc())
                            .limit(100)
                        ).all()
                    )
                    logger.info("Replaying %d missed events for tenant %s since %s", len(missed_events), organization_id, last_event_id)
                    for ev in missed_events:
                        ev_dict = {
                            "id": str(ev.id),
                            "source": ev.source,
                            "category": ev.category,
                            "severity": ev.severity,
                            "title": ev.title,
                            "description": ev.description,
                            "source_ip": ev.source_ip,
                            "target_uri": ev.target_uri,
                            "http_method": ev.http_method,
                            "status_code": ev.status_code,
                            "timestamp": ev.timestamp.isoformat(),
                            "is_replayed": True,
                        }
                        yield format_sse("security_event", ev_dict, event_id=str(ev.id))
            except Exception as e:
                logger.warning("Error processing Last-Event-ID %s: %s", last_event_id, e)

        # 2. Redis Pub/Sub streaming
        channel = f"preventx:events:{organization_id}"
        client = get_redis_client()
        pubsub = None
        start_time = time.time()
        last_heartbeat = time.time()

        if client is not None:
            try:
                pubsub = client.pubsub()
                pubsub.subscribe(channel)
                logger.info("Subscribed SSE stream to Redis channel %s", channel)
            except Exception as exc:
                logger.warning("Failed to subscribe to Redis channel %s: %s. Falling back to DB poll.", channel, exc)
                pubsub = None

        try:
            while (time.time() - start_time) < max_duration_seconds:
                now = time.time()

                # Heartbeat keepalive
                if (now - last_heartbeat) >= HEARTBEAT_INTERVAL_SECONDS:
                    yield ": ping\n\n"
                    last_heartbeat = now

                # Consume from Redis if available
                if pubsub is not None:
                    try:
                        msg = pubsub.get_message(ignore_subscribe_messages=True, timeout=POLL_TIMEOUT_SECONDS)
                        if msg and msg.get("type") == "message":
                            raw_data = msg.get("data")
                            if raw_data:
                                try:
                                    parsed = json.loads(raw_data)
                                    ev_id = parsed.get("id")
                                    yield format_sse("security_event", parsed, event_id=ev_id)
                                except Exception:
                                    yield format_sse("security_event", raw_data)
                            continue
                    except Exception as exc:
                        logger.warning("Redis pubsub error in SSE loop: %s", exc)
                        time.sleep(POLL_TIMEOUT_SECONDS)
                else:
                    # Non-Redis fallback sleep
                    time.sleep(POLL_TIMEOUT_SECONDS)

        finally:
            if pubsub is not None:
                try:
                    pubsub.unsubscribe(channel)
                    pubsub.close()
                except Exception:
                    pass
            logger.info("Terminated SSE stream for tenant %s", organization_id)

    event_generator = event_stream_generator

