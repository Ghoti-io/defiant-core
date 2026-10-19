# defiant-core

The Defiant kernel. It holds a request context, a fiber scheduler, an
offload pool and a yield watchdog. `cutil` keeps the fibers, the event loop
and the thread pool. `defiant-storage` keeps the writer queue; this library
calls it.

A request carries its tenant as caller-supplied bytes, its fiber, its
deadline and its yield bound. There is no current request on the thread.
Fibers of different tenants take turns: a body that returns
`GDEFCORE_TURN_AGAIN` has not called yield, and another tenant still runs.
A body that stays inside one turn past its yield bound is named by the
watchdog. A blocking call runs on the offload pool and the fiber resumes on
the thread that created it. A fiber that holds a storage write and then
waits for anything else has that write aborted.

```c
GDEFCORE_Sched * sched = NULL;
GDEFCORE_Request * request = NULL;
const uint8_t tenant[] = {'a'};

gdefcore_sched_create(NULL, 1, 0, &sched);
gdefcore_request_create(tenant, 1, 0, 0, NULL, &request);
gdefcore_sched_spawn(sched, request, body, NULL);
gdefcore_sched_run(sched);
gdefcore_sched_destroy(sched);
gdefcore_request_destroy(request);
```

## Building

```bash
make test PREFIX=/path/to/prefix
make test-valgrind test-asan check-symbols PREFIX=/path/to/prefix
```

Dependencies are `cutil` and `defiant-storage`, found only through pkg-config.
`make test` also runs `check-symbols`, `check-aliasing`, `check-seams`,
`check-prefix` and `check-labels`. Each of the three Defiant gates is shown
to fail on a planted defect.

The subject tests run on a key store chosen by `GDEFCORE_TEST_KEYSTORE`
(`memory`, the default, `sqlite` or `postgres`; documentation/subjects.md).
`make test` runs them on memory and, through `check-keystores`, on SQLite.
The Postgres arm is `make test-keystore-postgres`: it needs
defiant-storage-postgres, which builds only in that library's derived image,
and a server, which its `tools/pg-test.sh` starts:

```bash
sh ../defiant-storage-postgres/tools/pg-test.sh -- \
  "make test-keystore-postgres PREFIX=/path/to/prefix"
```

Without a server it fails naming the fix, or with `GDEFSPG_TEST_SKIP_SERVER=1`
prints `SKIPPED: postgres` and is not counted as passed.

## API

`gdefcore_request_create` copies the tenant bytes onto an opaque handle.
`gdefcore_sched_spawn` creates that request's fiber on the calling thread,
with `GCU_FIBER_DEFAULT_STACK_SIZE`. `gdefcore_sched_run` runs ready fibers
round-robin by tenant span. `gdefcore_sched_offload` runs a function on the
pool. `gdefcore_sched_yield` suspends the fiber. A full pool returns
`GDEFCORE_ERR_BUSY` and does not block. A deadline that passes during a wait
ends the fiber at the request boundary with `GDEFCORE_ERR_LIMIT`.

## Status

Milestone 1, story 6. Every public header is `@stability free`. Nothing is
released. Design: `documentation/scheduler.md`.
