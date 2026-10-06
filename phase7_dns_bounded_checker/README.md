# Phase 7 checker — DNS deadline correction

This is a local successor to the checker published at commit b82b21283a5df0f19bcb7eb11ca98947d3667dba. The previous checker and successful ROUTE run 37534849302 remain unchanged.

The correction isolates the fixed hostname lookup in an owned helper process. The observer must receive a complete bounded result, validate the exact expected address, and observe the original helper's successful exit and reaping within the original three-second operation budget before allowing a target connection. Part of that budget is reserved for terminating and reaping a stalled helper. A normalized DNS duration of 3,000 ms or more also prevents any target operation.

The sole hostname remains michel-pr20-377eb54-2-24-81-191.sslip.io and the expected IPv4 remains 2.24.81.191. One application resolver call may involve internal system resolver retries; it is not a promise of one DNS packet. ROUTE makes at most one subsequent TCP connection to port 443 and sends no application payload. It performs no TLS, HTTP, login, VPS configuration change, or native gate operation.

The parent owns the helper PID and pipe. Missing, partial, excessive, invalid, mismatched, or late output, failed exit, or uncertain helper closure cannot establish DNS success. No detached worker, background retry, configurable host, or caller-supplied helper command is exposed. Linux parent-death protection is a failure safeguard, not proof of universal scheduling or cleanup.

The existing strict request contract, finite phase plans, response parser, native package association, no-credential output, and Phase 7 BLOCKED status remain. Only the successor workflow identity and necessary resolver error codes may change in the contract. The 40-second observation ceiling, three-second operation budget and all native gate clocks are unchanged. Separate outer process and workflow timeouts remain emergency bounds.

Local fixture results qualify only the exact checked source and observed local environment. They do not qualify the GitHub runtime, TLS, HTTP access control, authentication stop, session expiry, private-port isolation, native cleanup, or full gate acceptance. A successful diagnostic never grants a later phase automatically.

## Local verification

One recorded focused offline run passed all 35 tests and 43 subtests. The two synthetic helper processes performed no DNS or socket activity. The success case exited and was reaped in 0.020761222 seconds. The stalled case received SIGKILL and was reaped in 2.520545957 seconds, before the original three-second deadline. The runner did not need to kill or reap either child itself. All 14 bound Python source files remained unchanged; there were no failed, skipped or expected-failure tests and no denied network/process operation.

The 33 other tests used controlled mocks to check exact output, malformed or oversized output, wrong addresses, expiry, cancellation, missing exit, uncertain ownership/cleanup, setup failure, and no subsequent target connection. Local reaping observations apply to these original helper PIDs; they do not prove arbitrary NSS/plugin descendants, remote DNS work, or a hard real-time operating system guarantee.

## Publication proposal

After focused offline verification and independent review, an exact create-only mapping may propose new files under phase7_dns_bounded_checker/ and a new manual workflow .github/workflows/phase7-dns-bounded-check.yml. Preserve every currently published blob. Use the same concurrency group as the predecessor so the two diagnostic workflows cannot execute simultaneously through this workflow configuration.

Publication and a new hosted diagnostic require a concrete owner decision; local preparation does not consume or replenish the prior run's allowance. No publication or target connection occurs merely by saving this package. Public repository source, fixed host/IP, nonsecret strict input, and workflow logs will be public if that proposal is accepted. Existing Pages automation may rebuild on publication. Additional spending is limited to $0.

Never supply a password, GATE_READY token, browser cookie, or session credential to the workflow. Dispatch only the reviewed exact commit on main, with fresh strict input, once, attempt 1. No rerun, retry, background polling loop, or automatic dispatch is part of the proposed operation. Keep cleanup_proven:false, control_authority:NONE, and phase7_acceptance:BLOCKED in result interpretation.
