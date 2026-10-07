# Phase 7 existing-provider capability check

This preparation answers whether an already running timesyncd provider exposes the two existing read-only properties required for retained clock diagnostics on the actual job. It also records kernel clock state before and after collection. It does not establish cross-machine alignment or open the Phase 7 gate.

The previous single kernel-only job returned `KERNEL_UNSYNCHRONIZED`. Its publication and dispatch allowances are consumed. This new workflow is a separate proposal requiring its own exact publication and single-run approval.

## Fixed behavior

The job verifies its public repository, main branch, reviewed commit, workflow, job, platform and first attempt. Pinned checkout removes persisted credentials. A source-bound entry point validates all five module byte hashes before loading their exact bytes into memory. The current environment is cleared before observation and the child executor supplies only a fixed minimal environment.

The existing unchanged sampler performs at most two observations, each containing two modes-zero kernel reads. Between them, the unchanged collector can make at most six requests in this order: existing owner, NTPMessage, PollIntervalUSec, the same packet, the same poll, existing owner. Properties are addressed to the first unique owner. Every busctl request disables automatic activation and interactive authorization. Missing provider, changed owner/sample, invalid response, process failure or uncertain closure stops the relevant path; there is no retry or fallback provider search.

An initial unsynchronized kernel may still be followed by provider diagnostics in this explicitly observation-only check. That refusal remains in the final result. A stable provider reply cannot clear it. No source changes a clock, starts a service, installs software, contacts an NTP server or probes the VPS or application.

## Process ownership and limits

The fixed `/usr/bin/busctl` path and every resolved alias/parent component must remain protected and root-owned. Only the owner query and two property-query argument forms are accepted. No arbitrary command, shell, stdin, environment or executable path can be supplied through the public executor API.

The collector has a ten-second observed call budget and four-second maximum requested call deadlines. The executor reserves 500 milliseconds of each ordinary deadline for cleanup, uses nonblocking pipes and caps combined stdout/stderr at 16,384 bytes. It terminates and waits for its exact child on failure. Already-late process creation or scheduling may require one additional cleanup window of at most 500 milliseconds. Any failure poisons reuse; an unconfirmed child remains explicitly unclosed.

The whole runtime check has a fifteen-second observed budget. The external owner is GNU `timeout --signal=KILL 20s` in normal process-group mode, under a two-minute job limit. Children keep that process group. If ownership remains uncertain, the entry point emits a fixed residual refusal, flushes it and stays alive for the external group kill. It must not be run with `timeout --foreground` or detached child sessions. Group termination is containment, not a client-reaped receipt or proof that a daemon method was canceled.

Process construction and OS scheduling are not universally preemptible. These limits are enforced paths and observed deadlines with an external owner, not a hard real-time guarantee. A terminated or incomplete job must be treated as refused; absence of a final result is never success.

## Data and interpretation

Public output contains source and job bindings, bounded kernel facts, monotonic/realtime collection brackets, sanitized provider digests and integer packet diagnostics. Raw provider replies, unique-owner strings and server reference identifiers are not published. Exact reply bytes stay in private process memory and are not uploaded as artifacts. Public output is capped at 49,152 bytes per main record, with a small fixed residual record possible on unknown closure.

The packet diagnostic preserves measured/exported integer components. Its uncertainty terms are not an independently verified present UTC error, a current post-correction residual or a future-validity guarantee. The job association identifies this workflow attempt; it is not machine attestation and does not qualify another ephemeral runner.

All outcomes retain no alignment, no execution or cleanup authority, no valid-through interval and `phase7_acceptance: BLOCKED`. Using clock evidence for gate planning still requires applicable runtime observations and a reviewed practical continuity/rate model covering each required machine relationship and interval. Existing five-second and native deadline requirements remain unchanged.

## Proposed execution scope

One create-only, non-forced publication at the reviewed parent and one manual capability dispatch at the resulting exact commit, including web dispatch fallback if needed and terminal read-only inspection. No retries or reruns. Standard public Ubuntu runner, no paid/custom runner or requested added spending. The pre-existing Pages workflow may rebuild on the main update. Checkout and log delivery use ordinary GitHub platform networking.

This file documents a prepared proposal. It is not authorization, and first-attempt checks are not a global ledger preventing a second independent dispatch.
