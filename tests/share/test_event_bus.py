from sqlalchemy.ext.asyncio import AsyncSession

from src.share.event_bus import AsyncEventBus, DomainEvent


async def test_event_bus_isolation_and_idempotency() -> None:
    """Tests that handler exceptions do not halt the publisher and subscription is idempotent."""
    bus = AsyncEventBus()

    call_count = 0

    class DummyEvent(DomainEvent):
        pass

    async def broken_handler(event: DummyEvent, session: AsyncSession | None) -> None:
        raise RuntimeError("Handler failure simulation")

    async def normal_handler(event: DummyEvent, session: AsyncSession | None) -> None:
        nonlocal call_count
        call_count += 1

    # Idempotent subscription test
    bus.subscribe(DummyEvent, normal_handler)
    bus.subscribe(DummyEvent, normal_handler)
    bus.subscribe(DummyEvent, broken_handler)

    # Publishing must not raise RuntimeError even when broken_handler throws
    await bus.publish(DummyEvent())

    # normal_handler should be called exactly once despite double subscription
    assert call_count == 1
