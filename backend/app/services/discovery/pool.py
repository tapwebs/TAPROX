"""Run a blocking function over many items on a bounded set of daemon threads.

Used for work the operating system may block on (an ARP probe, a reverse-DNS lookup). Results are
handed back to the *calling* thread one at a time, so all bookkeeping stays single-threaded.

Cancellation is cooperative: once `stop` is set or the deadline passes, no new item starts and
calls already in flight get `grace` seconds to finish. A call that is still stuck after that is
abandoned: its thread is a daemon, so it can neither hold the scan nor block process exit.
"""

import queue
import threading
import time
from collections.abc import Callable, Generator, Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Outcome[T, R]:
    item: T
    value: R | None
    error: Exception | None


def run_parallel[T, R](
    items: Iterable[T],
    fn: Callable[[T], R],
    *,
    workers: int,
    stop: threading.Event,
    deadline: float,
    grace: float = 3.0,
    abort_after_errors: int | None = None,
) -> Generator[Outcome[T, R]]:
    """Yield an Outcome per completed item. `deadline` is a `time.monotonic()` value.

    With `abort_after_errors`, no new item starts once that many calls have failed and none has
    succeeded: a failure that happens instantly (a refused syscall) would otherwise be repeated
    for every remaining item before the caller could react.
    """
    todo: queue.SimpleQueue[T] = queue.SimpleQueue()
    count = 0
    for item in items:
        todo.put(item)
        count += 1
    if count == 0:
        return

    done: queue.SimpleQueue[Outcome[T, R]] = queue.SimpleQueue()
    halt = threading.Event()  # set when the consumer stops early

    def should_halt() -> bool:
        return halt.is_set() or stop.is_set() or time.monotonic() >= deadline

    tally = {"errors": 0, "successes": 0}
    tally_lock = threading.Lock()

    def work() -> None:
        while not should_halt():
            try:
                item = todo.get_nowait()
            except queue.Empty:
                return
            try:
                value = fn(item)
            except Exception as exc:  # reported to the caller, never lost
                done.put(Outcome(item, None, exc))
                with tally_lock:
                    tally["errors"] += 1
                    if (
                        abort_after_errors is not None
                        and tally["successes"] == 0
                        and tally["errors"] >= abort_after_errors
                    ):
                        halt.set()
            else:
                done.put(Outcome(item, value, None))
                with tally_lock:
                    tally["successes"] += 1

    threads = [
        threading.Thread(target=work, name=f"tapnettrack-probe-{i}", daemon=True)
        for i in range(min(workers, count))
    ]
    for thread in threads:
        thread.start()

    received = 0
    stopped_at: float | None = None
    try:
        while received < count:
            now = time.monotonic()
            if stopped_at is None and (stop.is_set() or now >= deadline):
                stopped_at = now
            if stopped_at is not None and now - stopped_at >= grace:
                return
            try:
                outcome = done.get(timeout=0.05)
            except queue.Empty:
                if done.empty() and not any(t.is_alive() for t in threads):
                    return
                continue
            received += 1
            yield outcome
    finally:
        halt.set()
