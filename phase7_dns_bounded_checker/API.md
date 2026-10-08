# Ordinary checker timing helper

This draft candidate uses a separate fixed same-owner chrony monitor, the existing observed
conditional model and structural clock-pair validator. Importing `checker.timing`
does not read clocks, inspect a provider, create a process, issue a request or grant
live authority. No private R1 capture, journal or delivery dependency is imported.

## Entry points

1. `snapshot, runtime = parse_context(raw_bytes, request_context, actual_env, approved_commit)`
2. Inside the one existing upgraded `PhaseDeadline`: `clock, prepared = prepare(owner,
   snapshot, runtime, request_context, monotonic_ns=..., time_ns=...)`.
3. Compute `network_ns = (1 + len(contract.operations(phase))) * 3_000_000_000`.
   Call `clock.reserve(COLLECTION_NS + network_ns)`, record
   `collection_start_ns = clock.check()`, and invoke existing
   `monitor.collect_private(owner=owner, runtime_sha256=runtime, boundary=boundary,
   required_reserve_ns=network_ns)` once. Record `collection_end_ns = clock.check()`.
4. `evaluated = evaluate(collected, clock, prepared,
   collection_start_ns=collection_start_ns, collection_end_ns=collection_end_ns)`.
5. Before DNS, every operation, output completion and after owner closure, call
   `fresh(clock, prepared, evaluated, active=...)`. After closure use `active=False`
   and separately call the actual owner's `check_closed()`. Revalidate the ordinary
   request with `contract.validate` at the returned current microseconds / 1e6.
6. `evaluated.summary` returns a new safe summary dictionary: pair error bounds,
   immutable original owner/wall/horizon metadata and explicit conditional/unverified
   flags. Never output `collected.private`, input policy, endpoint evidence or pair
   bytes. The caller remains responsible for final public output size validation.

`Clock.reserve(required_ns)` uses strict greater-than remaining time and never
creates an owner. All collection, model, transport, normalization and closure work
spends the original exact 40-second interval. The ordinary route capability
phase `ROUTE` is outside this helper; it receives
no clock qualification by implication.

## Exact input

`raw_bytes` must be nonempty ASCII bytes at most 16,384 bytes. Duplicate keys,
floating-point/nonfinite JSON numbers, negative or out-of-range integers, arrays,
excessive nesting, non-ASCII decoded strings and unknown fields refuse. Whitespace
is allowed; binding uses canonical sorted compact ASCII JSON.

The top-level fields are exactly:

| Field | Contract |
|---|---|
| `schema` | Integer `2` |
| `record` | `ORDINARY_CHRONY_TIMING_CONTEXT` |
| `request_sha256` | SHA-256 of canonical JSON containing exactly the ordinary request's eight `contract.INPUT_KEYS` fields |
| `expected_commit` | Exact approved 40-hex commit, equal to actual `GITHUB_SHA` and `GITHUB_WORKFLOW_SHA` |
| `observation_lower_us` | Exactly original request `observed_epoch * 1_000_000`; no new earlier-origin claims in this version |
| `native_endpoint` | Existing exact `REVIEWED_CONDITIONAL_ENDPOINT` / `EXPLICIT_OPERATING_POLICY` schema with role `NATIVE` |
| `coordinator_endpoint` | Same schema, role `COORDINATOR`, required only for CLOSEOUT; otherwise null |
| `runner_profile` | Exact `ORDINARY_CHRONY_MONITOR_OPERATING_PROFILE`; actual daemon/configuration/source bindings are acquired inside the same job |

The actual environment must select the contract repository/id, workflow path,
main branch, workflow_dispatch event, first attempt, job `observe`, public repo,
Linux/X64 runner and nonzero actual run ID. The runtime digest is SHA-256 over
the canonical exact selected `ASSOCIATION_KEYS` projection, as in the retained
captured-phase helper. It is an actual-job association, not runtime attestation.

The profile is validated before collection and matched to the actual monitor
facts afterward. It fixes the Canonical Noble chrony 4.5 Hyper-V PHC profile,
source accuracy of one second, error growth of 1,000 ppm, and a maximum sample
age of 16 seconds. Those numbers are explicit engineering premises rather than
vendor guarantees. Observed correction, source, configuration and process filters
limit applicability but cannot prove future stability. On-disk configuration
continuity does not prove what the daemon loaded; loaded-config equivalence and
no edits remain explicit assumptions. No future daemon, source or configuration
hash must be guessed. See MONITOR_API.md and PROFILE_REVIEW.md for the exact
profile and its limits.

## Immutable interval and conditional meaning

`prepare` freezes canonical context, operating profile and request bytes in a
frozen `Prepared` record. It fixes one wall start and `horizon_us = wall_start_us
+ 40_000_000`. Coverage begins at the earlier of that start and the original
request observation lower bound. Profile and both applicable endpoints must cover
this whole interval before collection. The initial request must have more than
45 seconds of remaining expiry allowance and the retained full phase/deadline
planning margin. No later call recomputes a new now-plus-40 horizon.

The actual-shaped record must name the same owner bounds and be enclosed by the
current collection call brackets and wall observations. The monitor validates its actual record, matches the operating profile, and
materializes policy bindings from the observed facts. The retained arithmetic
checks both chrony snapshots and the complete modeled interval. Endpoint plus runner bounds are rounded outward to microseconds and must
be at most 5,000,000. The existing pair validator checks runtime labels, interval
coverage and bound scope at every freshness check.

`Evaluation` stores canonical pair bytes and original scalar bounds, also frozen.
Its summary property returns a fresh dictionary, so mutating returned summary
data cannot alter checked private pair records. Context/policy callback mutation
cannot alter the frozen snapshots. These in-process associations are not a
hostile-code sandbox, authentic source evidence, complete byte-copy accounting,
hard containment, policy-truth verification, private delivery or gate permission.

All successful timing results remain conditional, `alignment_established=false`,
`execution_authorized=false`, and `phase7_acceptance=BLOCKED`. Errors use fixed
`TimingError.code` values; caller output must never include arbitrary exception
text, policy contents or source/client identities. No execution or tests were
performed by the author while constructing this helper.

`initial_summary()` supplies the exact fixed refusal/unstarted shape for the
entrypoint. `public_summary(value)` reconstructs that exact allowlisted shape,
checks code/status/flag types, 0-or-1 collection calls, transport status, at most
two 0..5,000,000-microsecond pair bounds and any complete original interval.
Unknown fields and partial/altered interval shapes refuse. The public provider
mode is fixed `NONINTERACTIVE_SUDO_MONITOR`. The exact new private observation
schema remains distinct from the original kernel-qualified collector and from
synthetic test fixtures. No supplied profile creates authority or authenticates
clock truth. All offline results are reported separately from actual runner facts.
