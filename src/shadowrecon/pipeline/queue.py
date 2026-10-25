"""Asynchronous streaming queue and event bus for the ShadowRecon pipeline."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional, Set


@dataclass
class Event:
    """An event emitted by a pipeline stage (e.g. host discovered, finding recorded)."""
    topic: str
    data: Any
    source: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class AsyncEventBus:
    """Pub/sub streaming event bus backed by asyncio queues.

    Allows concurrent streaming between stages (e.g. crawler feeding
    fuzzers as URLs are discovered without waiting for entire crawl to finish).
    """

    def __init__(self) -> None:
        self._subscribers: Dict[str, Set[asyncio.Queue[Optional[Event]]]] = {}
        self._all_events: List[Event] = []
        self._closed: bool = False

    def subscribe(self, topic: str = "*") -> asyncio.Queue[Optional[Event]]:
        """Subscribe to a specific topic or '*' for all topics."""
        q: asyncio.Queue[Optional[Event]] = asyncio.Queue()
        if topic not in self._subscribers:
            self._subscribers[topic] = set()
        self._subscribers[topic].add(q)
        return q

    def unsubscribe(self, queue: asyncio.Queue[Optional[Event]], topic: str = "*") -> None:
        """Unsubscribe a queue from a topic."""
        if topic in self._subscribers and queue in self._subscribers[topic]:
            self._subscribers[topic].remove(queue)

    async def publish(self, topic: str, data: Any, source: str = "") -> Event:
        """Publish an event to all subscribers of `topic` and wildcard '*'."""
        if self._closed:
            raise RuntimeError("Cannot publish to closed event bus")

        event = Event(topic=topic, data=data, source=source)
        self._all_events.append(event)

        targets: Set[asyncio.Queue[Optional[Event]]] = set()
        if topic in self._subscribers:
            targets.update(self._subscribers[topic])
        if "*" in self._subscribers:
            targets.update(self._subscribers["*"])

        for q in targets:
            await q.put(event)

        return event

    async def stream(self, topic: str = "*") -> AsyncIterator[Event]:
        """Stream events for a topic asynchronously until sentinel (None) or bus close."""
        q = self.subscribe(topic)
        try:
            while True:
                item = await q.get()
                if item is None:
                    break
                yield item
        finally:
            self.unsubscribe(q, topic)

    async def close_topic(self, topic: str) -> None:
        """Signal completion of a topic to its direct subscribers."""
        if topic in self._subscribers:
            for q in list(self._subscribers[topic]):
                await q.put(None)

    async def close(self) -> None:
        """Close event bus and notify all listeners with sentinel."""
        if self._closed:
            return
        self._closed = True
        for topic, q_set in self._subscribers.items():
            for q in list(q_set):
                await q.put(None)

    @property
    def history(self) -> List[Event]:
        """Return all events published across the lifetime of the bus."""
        return list(self._all_events)
