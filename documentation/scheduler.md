# Scheduler

**Status:** describes what shipped in milestone 1, story 6.

The scheduler does not preempt. A request body runs until it returns, calls
`gdefcore_sched_yield`, or calls `gdefcore_sched_offload`. Returning
`GDEFCORE_TURN_AGAIN` is not a yield: the body did not ask to suspend, and
the scheduler still switches to the next tenant before calling that body
again. That is the fairness rule. A body that never returns from a turn
holds its thread; the watchdog names its request id and does not switch it
away.

The deadline is absolute `CLOCK_MONOTONIC` milliseconds. Zero means none.
While a fiber waits on an offload, the scheduler's loop wakes at the
deadline, destroys the fiber without unwinding it, and records
`GDEFCORE_ERR_LIMIT`. The body after the offload call does not run.

An offload whose pool queue is full returns `GDEFCORE_ERR_BUSY` on the
fiber's thread. The function is not started.

A held `GDEFSTOR_Write` is aborted, and the wait is not started, when the
fiber calls yield or offload. The port's own park inside
`gdefstor_write_begin` is the wait that write is allowed to make. This
library does not keep a second writer queue.

Stack size is `GCU_FIBER_DEFAULT_STACK_SIZE`.
