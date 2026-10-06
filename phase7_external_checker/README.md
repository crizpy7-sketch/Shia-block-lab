# Phase 7 fixed external observer

Prepared source, not authority to run. All checker code is standard-library Python. The only workflow trigger is an explicit manual dispatch at the reviewed publication commit. The checker never starts a native gate or changes a server. Current preparation includes 92 passing offline fixture tests; no hosted checker run or target probe has occurred.

## Scope

Fixed hostname: michel-pr20-377eb54-2-24-81-191.sslip.io. Fixed IPv4: 2.24.81.191. All actual sockets use the numeric IPv4. HTTPS retains normal certificate and hostname validation. No arbitrary URL, port range, proxy, password, session cookie, Authorization header, redirect following, dependency installation or automatic retry.

| Mode | Target operations after the single resolver call | Meaning |
| --- | --- | --- |
| ROUTE | TCP443 once; close without application payload | Observed name resolution and TCP reachability only; no TLS, HTTP or gate-readiness proof |
| CLOSED | Four protected HTTPS GETs; HTTP80 /api/ready; TCP43120,43121,9091 once each | Exact expected503/404, marker/cache checks and scoped private-port observations |
| LOGIN | CLOSED list plus HTML GET / and public /authelia/ | Exact anonymous401, exact same-origin302 and public-shell200 expectations |
| CLOSEOUT | Same fixed targets as CLOSED after reviewed native closeout | Observations only, always cleanup_proven:false |

The latter three modes are prepared functionality, not included in the proposed first ROUTE-run authority. No BROWSER/authentication-stop mode or phase advancement exists.

## Bounds and important limitations

One interpreter-owned40-second phase deadline, three-second operation eligibility deadlines, at most10 target connection reservations, header8192bytes/64fields, body16384bytes/+1overflow, own output32768bytes. Unsupported chunked/compressed/ambiguous responses, duplicate headers, incomplete bodies or failure to reach clean EOF cannot earn marker-absence success. Positive protected markers remain exposure even if later parsing fails. A timeout or unreachable private port remains inconclusive; refusal needs a successful same-phase verified HTTPS reachability control, and neither proves firewall causality.

Python signal handling does not guarantee preemption of a blocking C resolver call at exactly3seconds. One getaddrinfo call may include resolver-internal DNS retries. Late results are ineligible and cannot authorize a following TCP probe. Separate workflow process timeout45seconds plus1second forced-termination grace and job timeout2minutes are emergency bounds for the proposed ROUTE diagnostic, not proof of the original hard3second gate-plan bound. Offline fixtures use mocked IO/timing; no real DNS/TLS/signal timing was qualified. One successful future ROUTE run would establish observed behavior for that run only. Timed gate-phase use remains separately unqualified and requires exact authority addressing this limitation.

Workflow queueing can consume readiness and native time. No queue-duration guarantee, clock extension or retry exists. Current native cleanup35minutes/finish45minutes and approximately25minute browser requirement remain unchanged. CLOSED/LOGIN require conservative1665second remaining reserve and receipt validity at most120seconds; CLOSEOUT must fit the retained original finish cutoff. Clock-step detection does not establish initial cross-machine clock alignment. Missing valid alignment/phase/cutoff evidence blocks timed use. No target work is permitted during native authentication-stop.

## Public input and output

Manual inputs: approved_commit (exact40 lowercase hex) and request_json (ASCII<=2048bytes). Exact JSON fields: schema:1; phase; invocation; package_sha256; receipt_sha256; observed_epoch; expires_epoch; deadline_epoch. Epochs are integer UTC seconds. ROUTE uses null invocation/receipt/deadline and package_sha256 equal the reviewed disabled native gate binding b042dd5d1bba6e150a53ae1cf66271a14b6ce9bdff9111e7b35c20d197741945. The coordinator constructs fresh timestamps only after exact approval and consumes its submission reservation before dispatch. There is no live default request in this package.

For native-related modes, invocation is32lowercasehex, package/receipt hashes64lowercasehex, and cutoff is conservatively derived from privately retained same-attempt native evidence. A hash is correlation only, not signed attestation, authority or proof the remote endpoint remained in phase. CLOSEOUT binds a real terminal receipt, not an invented GATE_READY phase.

Both GitHub inputs and logs are public. Runner setup may show declared environment values before validation; rejected input is not made private by checker redaction. Never paste raw GATE_READY, native phase token/command, password, cookies, private config, response body or arbitrary headers into inputs. Only the coordinator-built strict nonsecret projection is appropriate. Checker-generated JSON contains fixed fields/enums, hashes, timestamps, selected status/cache/marker facts and fixed error codes, no raw exceptions or HTTP text.

GitHub RUN_ATTEMPT must equal1. That blocks reruns of a run, not another fresh dispatch with a different run ID. Concurrency is not a distributed one-use authorization lock. Each separately approved submission needs durable coordinator consumption before dispatch; a missing/ambiguous result consumes it and does not authorize retry. No settings, secrets, cache, artifacts, schedules, repository write permission or paid runtime are used by this workflow.

## Publication proposal

New files only in the existing public crizpy7-sketch/Shia-block-lab repository: this README, manifest.json, checker/{__init__,contract,main,response,transport}.py under phase7_external_checker/, and .github/workflows/phase7-external-check.yml. Preserve all existing blobs and compare exact current main before a non-forced update. Existing Pages may rebuild. The user must approve public fixed target details, the one publication and one ROUTE dispatch separately from any native gate attempt.

Sources: immutable gate source/External_Check_Plan/Phone_Run_Guide and local design/review/test evidence. Platform syntax: https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax ; Python signals: https://docs.python.org/3.12/library/signal.html . Standard GitHub-hosted runners for public repositories are the intended $0 runtime; recheck public/default runner eligibility before dispatch and do not enable paid features.
