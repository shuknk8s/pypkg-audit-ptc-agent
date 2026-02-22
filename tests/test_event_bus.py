"""Tests for the typed EventBus and AuditEvent SSE contract.

All tests are pure async -- zero LLM calls, zero network access.
"""
from __future__ import annotations

import json

import pytest

from src.agent.events import AuditEvent, EventBus


# ---------------------------------------------------------------------------
# T1 -- Single subscriber receives all events in order
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_single_subscriber_ordering():
    bus = EventBus()
    sub = bus.subscribe()

    events = [
        AuditEvent(event_type=f"event_{i}", package="test", data={"i": i})
        for i in range(5)
    ]
    for e in events:
        await bus.emit(e)

    received = []
    for _ in range(5):
        received.append(await sub.__anext__())

    assert [e.event_type for e in received] == [f"event_{i}" for i in range(5)]
    assert all(r.package == "test" for r in received)
    assert [r.data["i"] for r in received] == [0, 1, 2, 3, 4]


# ---------------------------------------------------------------------------
# T2 -- Multiple subscribers each get every event (fan-out)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fanout_multiple_subscribers():
    bus = EventBus()
    subs = [bus.subscribe() for _ in range(3)]

    await bus.emit(AuditEvent(event_type="alpha", package="pkg-a"))
    await bus.emit(AuditEvent(event_type="beta", package="pkg-b"))

    for sub in subs:
        first = await sub.__anext__()
        second = await sub.__anext__()
        assert first.event_type == "alpha"
        assert second.event_type == "beta"


# ---------------------------------------------------------------------------
# T3 -- AuditEvent.to_sse() produces spec-compliant SSE format
# ---------------------------------------------------------------------------
def test_to_sse_format():
    evt = AuditEvent(
        event_type="codegen_start",
        package="requests",
        timestamp=1700000000.0,
        data={"stage": "codegen"},
    )
    sse = evt.to_sse()

    # Must start with "data: " and end with "\n\n"
    assert sse.startswith("data: ")
    assert sse.endswith("\n\n")

    # Middle is valid JSON
    payload_str = sse[len("data: "):-2]
    payload = json.loads(payload_str)

    assert payload["event_type"] == "codegen_start"
    assert payload["package"] == "requests"
    assert payload["timestamp"] == 1700000000.0
    # Nested data dict survives round-trip
    assert payload["data"] == {"stage": "codegen"}


# ---------------------------------------------------------------------------
# T4 -- SSE stream simulation (end-to-end SSE contract)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_sse_stream_end_to_end():
    bus = EventBus()
    sub = bus.subscribe()

    lifecycle = [
        "codegen_start",
        "execute_complete",
        "interpret_start",
        "changelog_start",
        "finalize_complete",
    ]
    for et in lifecycle:
        await bus.emit(AuditEvent(event_type=et, package="flask", data={"stage": et}))

    # Collect SSE lines
    sse_chunks = []
    for _ in range(5):
        evt = await sub.__anext__()
        sse_chunks.append(evt.to_sse())

    # Concatenate into one SSE stream
    stream = "".join(sse_chunks)

    # Parse back: split on double-newline, drop empty trailing element
    raw_parts = stream.split("\n\n")
    raw_parts = [p for p in raw_parts if p.strip()]
    assert len(raw_parts) == 5

    recovered = []
    for part in raw_parts:
        assert part.startswith("data: ")
        payload = json.loads(part[len("data: "):])
        recovered.append(payload)

    assert [r["event_type"] for r in recovered] == lifecycle
    assert all(r["package"] == "flask" for r in recovered)

    # Each chunk conforms to EventSource format: "data: {json}\n\n"
    for chunk in sse_chunks:
        assert chunk.startswith("data: ")
        assert chunk.endswith("\n\n")


# ---------------------------------------------------------------------------
# T5 -- Subscriber cleanup on disconnect
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_subscriber_cleanup_on_close():
    bus = EventBus()
    sub = bus.subscribe()

    assert len(bus._subscribers) == 1

    # Consume two events
    await bus.emit(AuditEvent(event_type="a", package="p"))
    await bus.emit(AuditEvent(event_type="b", package="p"))
    await sub.__anext__()
    await sub.__anext__()

    # Close the async iterator -- triggers finally block that removes the queue
    await sub.aclose()

    assert len(bus._subscribers) == 0

    # Emitting after disconnect should not error
    await bus.emit(AuditEvent(event_type="c", package="p"))


# ---------------------------------------------------------------------------
# T6 -- EventBus with no subscribers does not error
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_emit_with_no_subscribers():
    bus = EventBus()
    # Should not raise
    await bus.emit(AuditEvent(event_type="orphan", package="none"))
