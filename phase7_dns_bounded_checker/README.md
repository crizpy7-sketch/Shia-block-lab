# Ordinary checker timing candidate

This draft updates the existing ordinary GitHub checker at
`phase7_dns_bounded_checker` and the existing
`.github/workflows/phase7-dns-bounded-check.yml` path in
`crizpy7-sketch/Shia-block-lab`. It has not been merged to main or dispatched. The
fixed target and ordinary network operation plan remain in the checker contract.
The previously consumed ROUTE observation cannot be repeated with this candidate;
the candidate refuses ROUTE before creating a collector or transport.

The new integration places the actual chrony collection and the complete ordinary
network batch under one original 40-second monotonic owner. It does not call an
inner checker that renews the phase deadline. The same owner retains the fixed
three-second operation boundaries and checks the remaining complete batch reserve
before collection and before creating a transport.

| Phase | Collection reserve | DNS and fixed operations | Total reserved | Time left within 40 seconds |
| --- | ---: | ---: | ---: | ---: |
| CLOSED | 6 seconds | 27 seconds | 33 seconds | 7 seconds |
| LOGIN | 6 seconds | 33 seconds | 39 seconds | 1 second |
| CLOSEOUT | 6 seconds | 27 seconds | 33 seconds | 7 seconds |

Admission requires strictly more than the stated reserve. Timing-context parsing,
collection validation, conditional arithmetic, and scheduling consume the
remaining time. Interpreter startup/imports and the original request preflight
precede this owner and remain inside the separate outer 45-second process guard. These figures describe reservation ceilings, not successful live
timing measurements or guarantees that a hosted runner completes LOGIN.

The real provider uses `/usr/bin/chronyc` directly with the fixed
`/run/chrony/chronyd.sock` Unix socket. Collection reserves four commands at one
second each and two kernel sampling collections at one second each. It does not
escalate privileges or change permissions. A prior capability observation using
`sudo -n` does not establish that this direct provider can access the socket in a
future job. Missing binary, unsuitable version, denied socket access, invalid
collection, or insufficient time refuses before the ordinary network batch.

The collection remains an unqualified local observation. Conditional arithmetic
uses explicit externally supplied operating policy and supplied native endpoint
evidence; it checks their association, interval coverage, and bounds. Structural
validation does not establish the truth of those external premises. Public output
retains `phase7_acceptance: BLOCKED` and `control_authority: NONE`; a computed
conditional timing bound does not authorize a native gate command, authenticate a
receipt, or prove cleanup. This ordinary candidate has no private R1 delivery,
encrypted result ingestion, or parent-finalizer dependency.

The workflow remains manual, fixed to the public repository, main ref, exact
reviewed commit, first run attempt, contents-read permission, one concurrency
group, pinned checkout, and Ubuntu 24.04. No workflow step retries. The outer
45-second guard and one-second kill grace contain the original inner 40-second
owner; they do not extend that owner. Inputs contain only the eight-field public
association request (at most 2,048 ASCII bytes), reviewed public timing context
(at most 16,384 ASCII bytes), and approved commit. Full GATE_READY receipts,
credentials, private captures, and secret values are not workflow inputs.

`build_manifest.py` reads only the seven fixed production package trees, parses
their imports as syntax data, and constructs the finite source manifest. It does
not import a candidate module or execute a provider. Its generated workflow block
pins the manifest hash, exact paths, per-file sizes and total source size. The
runtime loader rejects traversal, symlink source paths or parent directories,
unexpected Python files in pinned production directories, mismatched hashes, and
oversized inputs. Non-code documentation is not an executable source dependency.
Each Python source is capped at 65,536 bytes; the closure is capped at 64 files
and 262,144 total bytes; the manifest is capped at 8,192 bytes. Tests and local
build tools are excluded from the publication tree.

Publication and any new manual live dispatch remain separate concrete decisions.
No live attempt, target probe, VPS command, new workflow run, or ordinary receipt
has been issued by preparing these files.


# Ordinary checker timing helper

This draft candidate reuses the existing same-owner chrony collector, observed
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
   `collector.collect_private(owner=owner, runtime_sha256=runtime, boundary=boundary,
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
| `schema` | Integer `1` |
| `record` | `ORDINARY_CHECKER_TIMING_CONTEXT` |
| `request_sha256` | SHA-256 of canonical JSON containing exactly the ordinary request's eight `contract.INPUT_KEYS` fields |
| `expected_commit` | Exact approved 40-hex commit, equal to actual `GITHUB_SHA` and `GITHUB_WORKFLOW_SHA` |
| `observation_lower_us` | Exactly original request `observed_epoch * 1_000_000`; no new earlier-origin claims in this version |
| `native_endpoint` | Existing exact `REVIEWED_CONDITIONAL_ENDPOINT` / `EXPLICIT_OPERATING_POLICY` schema with role `NATIVE` |
| `coordinator_endpoint` | Same schema, role `COORDINATOR`, required only for CLOSEOUT; otherwise null |
| `runner_policy` | Existing exact `EXPLICIT_CHRONY45_POLICY_CLAIMS` schema, using two `CURRENT_JOB` placeholders described below |

The actual environment must select the contract repository/id, workflow path,
main branch, workflow_dispatch event, first attempt, job `observe`, public repo,
Linux/X64 runner and nonzero actual run ID. The runtime digest is SHA-256 over
the canonical exact selected `ASSOCIATION_KEYS` projection, as in the retained
captured-phase helper. It is an actual-job association, not runtime attestation.

The policy's top-level `runtime_sha256` and `daemon.runtime_sha256` must both
literally be `CURRENT_JOB`. `prepare` replaces only these two fields with the
digest of actual selected job fields. It infers no source identity, daemon
version, loaded configuration, accuracy, drift, sample age or continuity facts.
Those values and their evidence/review hashes must already be concrete external
claims. Chrony semantics are exact 4.5. The existing policy requires explicit
UTC timescale-error inclusion, no unaccounted steps, no restart/source change,
and retrospective projection permission; this narrower caller requires all
three continuity flags true before provider collection.

Source selectors match the retained collector grammar: `^` and `=` accept only
numeric IPv4/IPv6 addresses; IPv4 reference IDs must equal the uppercase packed
address hex. `#` accepts only one-to-four-character `[A-Za-z0-9_-]` refclock labels
and their exact zero-padded uppercase reference hex. IPv6 reference-ID derivation
is not inferred. Arbitrary free-form source labels and DNS names refuse.

## Immutable interval and conditional meaning

`prepare` freezes canonical context, materialized policy and request bytes in a
frozen `Prepared` record. It fixes one wall start and `horizon_us = wall_start_us
+ 40_000_000`. Coverage begins at the earlier of that start and the original
request observation lower bound. Policy and both applicable endpoints must cover
this whole interval before collection. The initial request must have more than
45 seconds of remaining expiry allowance and the retained full phase/deadline
planning margin. No later call recomputes a new now-plus-40 horizon.

The actual-shaped record must name the same owner bounds and be enclosed by the
current collection call brackets and wall observations. The existing observed
model checks both snapshots, selected source agreement and the complete supplied
policy. Endpoint plus runner bounds are rounded outward to microseconds and must
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
mode is fixed `DIRECT_SOCKET_ONLY`; the caller may not use this projection for
a privileged, network or fallback provider. A historical sudo collection does
not qualify current direct socket access.
