# Ordinary chrony monitor: pre-test source review

Verdict: the frozen monitor and schema-2 checker integration are suitable for one guarded offline check with bytecode writing disabled. This reviewer executed no candidate imports, tests, providers or network operations. This is not live-execution approval or a claim that an actual hosted runner matches the profile.

`main.run_once` parses `ORDINARY_CHRONY_TIMING_CONTEXT` inside the sole original 40-second owner. The frozen `runner_profile` is checked before collection. Actual source/daemon/config associations are materialized after six ordered same-owner captures: VERSION, FACTS, TRACKING, SOURCES, TRACKING, FACTS. No future runner hashes are invented. Current call brackets, original interval coverage, runtime/request/commit binding, final in-owner serialization and post-closure checks remain enforced.

Six one-second component reservations plus the complete unchanged network plan require strictly more than 39 seconds for LOGIN, or 33 seconds for CLOSED/CLOSEOUT. Metadata, parsing and arithmetic spend the remaining original allowance. Privileged commands are fixed noninteractive sudo tuples with internal timeout: tracking/sources 0.7 seconds plus 0.1-second kill grace; metadata 0.8 plus 0.1. Parent reads stop at 0.9 seconds with the last 0.1 reserved for direct closure. No service, clock, NTP initiation, shell, caller-controlled command or retry was added.

Clean nonzero exit with EOF, direct reaping and closed pipes may refuse immediately. Timeout status, parent kill or uncertain direct closure retains the same child handle and bounded polls through the original phase deadline; no replacement timer or target work starts. Privileged descendant cleanup remains unknown. Holding the original owner does not turn the outer process guard into proof of privileged descendant termination.

Review defects corrected before this verdict:

- Daemon argv now accepts only the exact binary and optional unique `-F1` and fixed `-f`; mode switches, alternate configurations and positional directives refuse.
- Configuration reads now traverse only the root configuration's bounded active include/confdir/sourcedir graph. Inactive directory files no longer supply refclock facts.
- Parent, child-creation, helper and daemon time-namespace association is checked.
- `CollectionError` now maps to intended fixed timing refusal codes.
- Tests cover the uncertainty hold with fake child handles, selector, pipes, clock, reads and sleeper.

Protected reads reject observed symlink components, non-root ownership and writable protected paths, then use final-component `O_NOFOLLOW` and capped regular-file reads. This is conditional local association under the no-edit premise, not atomic whole-path attestation. Metadata caps include 512 proc entries/256 PIDs, 64 daemon descriptors, eight configuration files, 16 KiB per configuration and 64 KiB total, 2 MiB daemon executable, 4 MiB package status, and 4,096-byte combined capture output. Oversized output refuses; maximal allowed intermediate list shapes are not promised to fit the final output cap.

The new chrony path makes zero kernel reads and does not relabel kernel `STA_UNSYNC` as success. The original generic sampler/collector/model remain unchanged. On-disk config equality and package MD5 matching remain observations, not proof of loaded configuration or authenticity. Accuracy of one second, growth of 1,000 ppm, sixteen-second sample age and continuity are explicit conditional operating premises. Hyper-V labels and chrony skew do not prove them. Truth, alignment, execution authority and Phase 7 acceptance remain false/BLOCKED.

Practical pair-budget limit: the retained hypothetical native envelope of 4.283971 seconds leaves only 0.716029 seconds for the runner and cannot pass this profile's one-second source allowance even before growth/bracket terms. Only the actual fresh native-plus-runner sum can decide eligibility; the five-second check is unchanged.

The harness guards sockets, processes, threads, writes, native providers and signals before candidate imports. New real monitor/facts entrypoints are guarded; direct capture-frame tests explicitly supply fakes. Parser malformed examples still use incomplete contexts and do not isolate every parser rule; source review supplements that limited test coverage. The review-directory path changes preserve local and published test imports, while manifest building still selects only the seven production trees. No native bridge or launcher execution is part of this proposed check.

## Source pins

| File | SHA-256 |
|---|---|
| `checker/main.py` | `a96772028243f3503ea282dea8ca54b94b8a7282c01ab2ff4d5fdc1d72a4fddb` |
| `checker/timing.py` | `b19d2e0c02b505826ddb17e9d86a5dbf526c52436f98b35b13d4da174c6dad5e` |
| `phase7_live_adapter/monitor.py` | `007925f60d3cee8455bc3c73c14b23e46566493c1695cd8c643f10308dc1180e` |
| `phase7_live_adapter/monitor_facts.py` | `01e8ce159a68f3f6feaf4445781eeed7af50b1c67d9318f994a196ef2b4dcfcb` |
| `test_monitor.py` | `64fd7696c26ae0f35bf07f75719c4e647f8e2205788855a6debcf63e611cbcf7` |
| `test_timing.py` | `114f12ac051750c49611379231274bf8737d342306f4e642e6fe6c0e4e8e0352` |
| `offline_check.py` | `cb318d60fb284c2d7a2ed90b86bbe100a3ec2c494fc9489d33fbe0e26960f08a` |
| `build_manifest.py` | `d968e1ee084c0e1033861d0677d9df88a2f825e0ab0f9f4808196a801292e333` |
| `loader_check.py` | `a35c60a1bf173966678b2d0320052997fd89db5f27dfd9cbff6e1788b74261ee` |
| `MONITOR_API.md` | `3049255289aeed8d56bbcd68672209628fcf158c5dff8ddc2c04441e037a3002` |
