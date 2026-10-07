# Read-only local clock-model sampler

`sampler.py` reports two immediate kernel clock-model snapshots using libc
`adjtimex` with a fresh, completely zeroed structure and `modes=0` on each call.
It accepts no command-line arguments, cannot select clock-setting modes, and
does not contact a time server, resolve a host, open a target socket, launch a
process or thread, start a service, write a file, or import gate/checker code.
Standard Python module and dynamic-library loading may read local files.

The implementation supports only Linux, little-endian x86_64 LP64 with the GNU
libc interface. Before loading the function it checks pointer/integer sizes,
every structure offset, the 208-byte size and 8-byte alignment. It then checks
the GNU libc symbol and declares the exact ctypes pointer argument and integer
return type. Missing interfaces or unsupported layouts produce a fixed refusal.
The ABI and units follow the [Linux adjtimex interface](https://man7.org/linux/man-pages/man2/adjtimex.2.html).
The [GNU libc manual](https://www.sourceware.org/glibc/manual/2.38/html_node/Setting-and-Adjusting-the-Time.html)
explains why kernel model values are assumptions. Merely importing this module
does not call `adjtimex`.

## API and collection policy

`collect(adapter, clock)` is the injectable collector. `adapter()` supplies one
exact dictionary containing the integer keys in `RAW_KEYS`; `clock` supplies
`monotonic_ns()` and `time_ns()`. Successful collection makes exactly two reads,
without sleeps or retries. The order for each is monotonic-before,
realtime-before, kernel query, realtime-after, monotonic-after. A malformed
dependency, read failure or already spent budget ends collection early.
`NativeAdapter` is the production adapter; `SystemClock` supplies the standard
library clocks. `collect_native()` invokes that pair and sanitizes initialization
failures. `encode_result` is an alias of `serialize`. Neither the injectable API nor its output authenticates the
caller or the runtime; independent execution/source association is required.

Every clock reading must be an exact nonnegative integer within signed 64-bit
range. Raw fields must be exact integers in their validated signed/unsigned
ranges. Error/precision/jitter values must be between zero and 10^12 raw units;
frequency/tolerance/stability values are limited to one million ppm scaled by
65,536. These are broad malformed-value limits, not claims about physical error.
The returned clock fraction must be normalized. Negative discipline offset and
frequency values are retained exactly.

The complete pair has a fixed one-second monotonic budget, inclusive at the
boundary. A completed read that spends it prevents another read. This is an
observed deadline: Python cannot preempt a stalled libc call or scheduler with
this design. An external owner should impose a short timeout covering module
loading and both reads. The sampler never creates that process itself.

Usable observations require nondecreasing monotonic and realtime brackets,
`TIME_OK` from both reads, unchanged status, zero returned modes, known status
bits, and no unsynchronized, hardware-error, leap or PPS-fault status. `STA_PLL`
alone is not required. Kernel timestamps must lie inside their corresponding
realtime brackets with inclusive allowance of one reported time unit: one
nanosecond under `STA_NANO`, otherwise 1,000 nanoseconds. This includes
microsecond quantization at the bracket edge.

A round's realtime span may not exceed its monotonic span by more than the
explicit one-millisecond rounding tolerance. For both rounds, intervals
`[realtime_before - monotonic_after, realtime_after - monotonic_before]` must
overlap within that tolerance. These checks can detect some clock steps; two
nearby samples do not prove absence of all steps or future stability. No
rounding tolerance is added to any gate margin.

## Output and limits

`collect` returns a fixed schema with either `KERNEL_MODEL_OBSERVED` or
`REFUSED`, a fixed diagnostic code and up to two sanitized numeric samples.
`serialize` emits one ASCII JSON line including its final LF, capped at 8,192
bytes. It validates the exact result and sample schemas, normalized sample
values, and fixed authority flags before emitting them. No exception text,
environment dump, credentials or hostname is emitted.
The entry point returns exit status 0 for an observed model and 2 for refusal.
It does not calculate its own source hash; an owner must bind the exact source
bytes and the actual execution/runtime in a separate receipt.

`offset_ns` normalizes the signed discipline-state offset. Returned kernel time
uses nanoseconds when `STA_NANO` is set, otherwise microseconds.
`reported_maxerror_ns`, `reported_esterror_ns` and `reported_precision_ns` always
convert microseconds to nanoseconds, independently of `STA_NANO`. Raw `freq`,
`tolerance`, `ppsfreq` and `stabil` retain their scaled-ppm integers. `jitter` is
preserved raw without claiming a normalized unit.

The kernel supplies model values. A synchronized state, low maxerror, small
offset or two consistent reads does not establish provider identity, last time
sample age, actual UTC error, measured drift or future valid-through coverage.
The sampler does not create `SUPPLIED_CLOCK_ALIGNMENT`, combine runtime error
budgets, issue native commands, renew deadlines or establish cleanup.

Every output therefore retains `OBSERVATION_ONLY`, `gate_action: NONE`,
`phase7: BLOCKED`, both alignment flags false, `execution_authorized: false`,
`cleanup_proven: false` and `valid_through: null`. A coordinator observation
cannot qualify a VPS or a later GitHub runner. Source and execution binding must
be reported separately; qualifying the actual two runtime relationships still
needs reviewed evidence covering each required interval.

## Hosted feasibility workflow

The companion `.github/workflows/phase7-clock-feasibility.yml` is manual only.
It requires the exact reviewed commit in `approved_commit`, public repository
ID 1316595124, main, first run attempt and the expected workflow/job identity.
The workflow pins checkout, grants only contents read, removes checkout
credentials, reads the sampler once, checks its fixed SHA-256 and executes those
same bytes from memory. No request JSON, gate token or target address is accepted.

It uses the standard `ubuntu-24.04` runner, a two-minute job timeout and a
five-second process timeout with one-second kill grace. These are platform and
process containment policies, not a scheduling guarantee. The collection itself
does not initiate network calls; GitHub checkout and job/log delivery use the
platform's ordinary networking. There is no install, sudo, cache/artifact action,
service query, provider activation or time change. Platform caching is not
asserted disabled.

One capped JSON record binds the observation to source bytes and the GitHub
repository/commit/run/attempt/job association. That association is not machine
attestation and does not apply to a later ephemeral runner. The first-attempt
condition blocks the workflow's rerun path; it cannot enforce a global limit on
independent manual dispatches. Execution scope must separately limit dispatches.
Sanitized clock data and job association are public in the job log. The complete
record is capped at 12,288 bytes. No automatic follow-up or retry is defined.
