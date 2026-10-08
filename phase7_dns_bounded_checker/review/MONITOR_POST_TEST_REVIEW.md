# Independent monitor post-test review — CHECK04

Reviewed the final frozen source and retained evidence on 2026-10-08. The final candidate is suitable for packaging and draft code review on the strength of the bounded synthetic checks below. This review does not authorize or qualify a live ordinary gate. Phase7 acceptance remains `BLOCKED`.

I read source and recorded results, independently hashed the current files, and compared the manifest's sizes and hashes. I did not import the candidate, execute tests, call providers, access target networks, or dispatch a workflow.

## Evidence reconciliation

| Evidence | Independently checked result |
| --- | --- |
| `ORDINARY_CHECK_04.json` | 25 test methods, zero failures/errors/skips; all six reported guard counters zero; `source_unchanged: true` |
| Python source closure | All 29 recorded SHA-256 values equal the current 29 Python files, with no extra Python file |
| `LOADER_CHECK_04.json` | Six cases pass; valid input reaches one stub launch; bad manifest, changed module, extra Python, symlink source and oversized input refuse before a stub launch |
| Loader operational scope | Candidate not imported or started; reported network/process/thread counters zero |
| `manifest.json` | All 24 production hashes and sizes match current files; total 212,480 bytes; manifest 3,374 bytes |
| Workflow | Hash matches the loader evidence; embedded manifest hash and 212,480-byte total match the current manifest; trigger remains manual |
| History | CHECK01–03 results and root pre-test amendments remain present. CHECK02 result and loader hashes still equal the independently recorded earlier values. No prior record was overwritten by this review. |

The 25 methods comprise 12 timing methods and 13 monitor methods. CLOSED, LOGIN and CLOSEOUT are synthetic subcases, not live checks. Elapsed time is 83,401,551 ns for the guarded harness; it is not real process/clock/deadline qualification. The existing malformed-input examples remain limited to the cases encoded in the tests, rather than exhaustive coverage of every parser rule.

## Final source amendments

`phase7_live_adapter/monitor.py:32` and `:132` now hold the original ownership interval even if a spawn attempt returns no handle. The hold uses the existing deadline and bounded polling/sleep, introduces no retry or fresh timer, and leaves the missing handle unknown. The no-handle regression supplies a raising fake spawn function and fake clock/sleeper, checks one fixed command attempt and the unchanged 40-second deadline, and requires false cleanup flags with `DIRECT_RESOURCE_CLOSURE_UNPROVEN`. This resolves the previously identified early-return ownership gap. It does not prove that a child never existed, that a missing child was reaped, or that privileged descendants terminated.

`phase7_live_adapter/monitor.py:324` permits a configured PHC path to be either `/dev/ptp_hyperv` or its exact observed resolved device. The helper still binds that alias to a character device, the Hyper-V clock name and the daemon's open device. The added regression accepts observed `/dev/ptp0` and rejects `/dev/ptp1` while the observed device remains `/dev/ptp0`. This admits two names for the same observed device, without an alternate provider or source-truth claim.

The unchanged guard harness blocks real sockets, processes, provider entry points, signals, threads and writes; capture-frame tests use explicit fake factories, pipes, reads and sleepers. This is synthetic boundary verification, not a general hostile-code sandbox proof. Both amendments were examined after execution using the retained root pre-test amendments; this document does not retrospectively claim independent pre-test approval for CHECK03/04.

## Limits retained

Collection remains six one-second reservations within the original 40-second owner, with fixed read-only monitor commands, strict phase reserves and no second collection phase. Loaded-config equivalence, source accuracy and continuity remain explicit premises. Actual hosted-runner compatibility, fresh native/runner/coordinator observations and the unchanged five-second pair bound remain unqualified by these checks. Privileged descendant cleanup and UTC authority remain unproven. The public summary remains conditional and cannot promote these tests into gate acceptance.

In particular, the historical 4.283971-second native envelope leaves only 0.716029 seconds before the five-second pair limit; it cannot combine successfully with the profile's one-second runner source allowance. A fresh native observation may differ. This review changes neither that arithmetic nor the ordinary route's acceptance predicate.

## Final pins

| File | SHA-256 |
| --- | --- |
| `ORDINARY_CHECK_04.json` | `a4e816c7cc2ebb26bb544772a7b9ec12a65d11735a3a1aa4dea180e439fb5f35` |
| `LOADER_CHECK_04.json` | `4a8e6d20b07178fb04011cf9d55c9e0c197bc732eb807832ed3619788d837c1e` |
| `manifest.json` | `a3ca2841424761a551be8caec57f68654299d23e7a1114f64e96626efa8257c4` |
| `.github/workflows/phase7-dns-bounded-check.yml` | `3e8ea6b16406f0e87e43c0e708103ada842513b355a5c6fa74a3df2b22cefb37` |
| `phase7_live_adapter/monitor.py` | `341a17f69c1cfd7cd68734ffd52ed85e242f87468a30a8eb2b5ab7896f267ed2` |
| `phase7_live_adapter/monitor_facts.py` | `01e8ce159a68f3f6feaf4445781eeed7af50b1c67d9318f994a196ef2b4dcfcb` |
| `test_monitor.py` | `ea9e0540c6cd184b41b40f07360803b593eb7d61bca356091e5d1fb6996a6805` |
| `MONITOR_API.md` | `82956cc1b9cb6b7b10b7f26b72ae22bda448bcc4cb2895c2b5338ea487e4ea50` |

Reviewer: temporary Quality Gate (`quality_review`). No further test run was requested or performed by this reviewer.
