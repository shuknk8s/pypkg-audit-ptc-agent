"""Typed event bus -- multiple async consumers can subscribe.

Terminal (Rich), SSE (web UI), and structured logging can all consume
the same events without changes to the audit pipeline.
"""
from __future__ import annotations

import json
import time
from asyncio import Queue
from dataclasses import asdict, dataclass, field
from typing import AsyncIterator


@dataclass
class AuditEvent:
    """A single typed event emitted during an audit run."""

    event_type: str
    package: str
    timestamp: float = field(default_factory=time.time)
    data: dict = field(default_factory=dict)

    def to_sse(self) -> str:
        """Format as a Server-Sent Event line.

        Spec: https://html.spec.whatwg.org/multipage/server-sent-events.html
        """
        return f"data: {json.dumps(asdict(self))}\n\n"


class EventBus:
    """Fan-out event bus -- each subscriber gets every event."""

    def __init__(self) -> None:
        self._subscribers: list[Queue[AuditEvent]] = []

    async def emit(self, event: AuditEvent) -> None:
        for q in self._subscribers:
            await q.put(event)

    def subscribe(self) -> AsyncIterator[AuditEvent]:
        q: Queue[AuditEvent] = Queue()
        self._subscribers.append(q)

        async def _iter() -> AsyncIterator[AuditEvent]:
            try:
                while True:
                    yield await q.get()
            finally:
                if q in self._subscribers:
                    self._subscribers.remove(q)

        return _iter()
