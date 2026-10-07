# One existing-chrony capability inspection

Prepared locally; no publication, live invocation or execution approval is implied. This is a fixed diagnostic inspection, not a clock adapter, clock model or gate attempt. Phase 7 and all alignment/acceptance flags remain blocked/false even if a report is obtained.

## Exact proposed actions

The entry first validates the exact public repository, main ref, approved commit and workflow SHA, workflow `phase7-chrony-capability.yml`, first run attempt, observe job, Linux/X64 and run ID. Failure precedes binary/provider access. The three fixed executables must be regular root-owned executable files under root-owned non-group/world-writable `/usr/bin`; symlink paths refuse.

1. If the fixed chronyc path passes inspection, one unprivileged version command: `/usr/bin/timeout --signal=KILL 2s /usr/bin/chronyc --version`.
2. After a successful bounded version parse and unchanged chronyc/timeout identities, exactly one tracking command: `/usr/bin/sudo -n -- /usr/bin/timeout --signal=TERM --kill-after=1s 3s /usr/bin/chronyc -n -c -h /run/chrony/chronyd.sock tracking`.

The proposal explicitly includes this fixed noninteractive sudo read from the outset. It is not an escalation after a failed ordinary-user attempt. Chrony's local command socket normally requires root/chrony access. The command contains no install/start/restart, time adjustment, forced measurement, waitsync, alternate socket, remote host or network fallback. It has one invocation; the client's existing protocol retransmission behavior is not represented as a count of daemon calls. Missing/unapproved binaries, denied sudo, missing socket or unsupported output produce explicit refusal. A valid numeric shape from another bounded version is retained as unqualified format evidence.

`approved_chronyc_available` is null before inspection, true only after the protected path passes, otherwise false for a failed inspection attempt. False is not a claim that the package physically does not exist.

## Capture and containment limits

Version and tracking have parent observation deadlines of 3 and 6 seconds. Stderr and stdout share a 4096-byte memory cap; overflow clears captured text, saturates byte counts at 4097 per stream, marks counts inexact, and continues bounded draining until wrapper completion/deadline. No raw stream content is printed. Exit and pipe closure are separately observed; pipe EOF alone is not treated as child completion.

The privileged GNU timeout sends TERM after 3 seconds and KILL after another second if necessary. An ordinary Python parent cannot claim to kill/reap all root-owned descendants. Parent cleanup addresses only its direct Popen handle, waits at most another 0.5 seconds, and closes its own pipes. Public evidence distinguishes direct-wrapper reaping, parent pipe closure, EOF, timeout/unknown containment, and privileged-child cleanup. The last remains unproven; the existing daemon is never targeted for cleanup.

Neither timer guarantees a hard wall-time under arbitrary scheduler/PAM/process failures. A sudo stall before its inner timeout starts is an explicit containment risk, not silently covered by that timer. Timeout statuses 124/137, parent-deadline intervention, missing EOF or unproven parent resource closure emit refusal/uncertainty. The owner then remains monitored for the workflow's required external `timeout --signal=KILL 20s`; that eventual termination is containment, not a privileged-descendant reaping receipt. No further command or retry is launched.

## Exact scalar projection

Upstream 4.5 `client.c` produces 14 comma-separated tracking fields; no CSV quotation is assumed. Fixed decimal places follow `print_report` and `process_cmd_tracking`. `util.c` specifies the reference timestamp's nine fractional digits. Retain the exact finite version token; omit build-feature text. Only the exact token `4.5` matches this reviewed source contract, and even that is not proof of binary/runtime semantics.

| Index | 4.5 field | Public handling |
| --- | --- | --- |
| 0 | Reference ID | Validate 8 uppercase hex digits; discard |
| 1 | Reference name/address | Bounded printable field; discard |
| 2 | Stratum | Integer 0–65535 |
| 3 | Reference time | 9 decimals → Unix nanoseconds string |
| 4 | System correction | 9 decimals → nanoseconds string |
| 5 | Last offset | 9 decimals → nanoseconds string |
| 6 | RMS offset | 9 decimals → nanoseconds string |
| 7 | Frequency | 3 decimals → milli-ppm string |
| 8 | Residual frequency | 3 decimals → milli-ppm string |
| 9 | Skew | 3 decimals → milli-ppm string |
| 10 | Root delay | 9 decimals → nanoseconds string |
| 11 | Root dispersion | 9 decimals → nanoseconds string |
| 12 | Update interval | 1 decimal → deciseconds string |
| 13 | Leap text | Fixed enum only |

Every scaled integer and monotonic timestamp is a decimal string, so JavaScript serialization cannot round it. The parser bounds tokens and signed integer magnitude, rejects exponent/nonfinite/extra-line/extra-field inputs, and requires nonnegative reference time. Numeric projection from an unknown version is explicitly `FORMAT_ONLY_NOT_CLOCK_EVIDENCE`; positions describe the reviewed shape, not verified unknown-version semantics. No source identifier, hostname/address, raw stderr, raw version features or hash of private fields is published. No uncertainty bound or synchronization decision is calculated.

## Primary source basis

- [Chrony 4.5 client source, maintainer mirror](https://github.com/mlichvar/chrony/blob/4.5/client.c), blob `7cfefba274e1bc343400f008b36a6933acbbcc5d`: version formatter, CSV conversion and tracking field order.
- [Chrony 4.5 utility source](https://github.com/mlichvar/chrony/blob/4.5/util.c), blob `a4c8288b38ca11b6e5a81076afcfbbd02d7540cb`: timestamp formatter.
- [Official chronyc 4.5 manual](https://chrony-project.org/doc/4.5/chronyc.html): local socket access, explicit `-h`, `-n`/`-c`, and monitoring-only tracking.
- [GNU timeout manual](https://www.gnu.org/software/coreutils/manual/html_node/timeout-invocation.html): signal/kill-after behavior and ambiguity of status 137.

The project identifies its upstream repository at [chrony GitLab](https://gitlab.com/chrony/chrony). The exact 4.5 source bytes above were fetched read-only from the maintainer's mirror; no code or live utility was run during preparation. Root owns the separate synthetic tests, final review and exact workflow binding.
