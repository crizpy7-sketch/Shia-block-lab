# Phase 7 bounded transport qualification

Prepared proposal only. Publication and execution require separate owner authorization.

One manual GitHub Actions job runs six fixed synthetic cases in one constrained Docker container on the standard Ubuntu 24.04 runner. There is no discovery of the old test suite, application deployment command, automatic retry, artifact upload or cache upload.

`contract.json` binds the repository, image digest, source hashes and limits. The workflow checks exact bytes before the host supervisor starts. The container preflight checks its own effective limits and waits for an external release token before executing the fixtures. The fixed runner reuses the unchanged transport's bounded reporting and retains original stop and separate emergency-cleanup evidence.

The limits of 1 CPU, 256 MiB memory, no swap, 32 tasks and 16 MiB regular-file scratch apply to the workload container. They do not cap the entire GitHub VM, Docker daemon or outer supervisor. Kernel pseudo-filesystems are not ordinary-file scratch; this is a trusted fixed synthetic workload, not an adversarial sandbox.

Host limits: one image pull (45 seconds), setup (30 seconds), workload including preflight (25 seconds), separate disposal observation (5 seconds), final log flush (1 second), at most ten owned Docker CLI invocations and 256 KiB exported evidence. The workflow's three-minute limit is a coarse platform safeguard. No timing setting guarantees scheduler/API completion or VM destruction within that period.

The six cases are normal VM completion, normal PSI pair, malformed result, oversized result, ignored TERM with a stalled collector/full pipe, then an expired original deadline. At most twelve fixture children are created, two at a time. Each original Session budget remains two seconds. Separate emergency cleanup never upgrades an earlier UNKNOWN.

One authorized dispatch consumes one allowance even if setup refuses or times out. `run_attempt == 1` rejects a rerun of the same run; it does not enforce a global one-dispatch allowance. The operator must record the original run ID and not dispatch again.

Acceptance requires complete original run/job logs and terminal status, matching source bindings, six complete case records, original owned-handle closure evidence, and the supervisor's separate container stop/removal evidence. Job success alone is insufficient. No source here claims a separate GitHub VM-destruction receipt or repairs historical UNKNOWNs. Phase 7 application acceptance remains blocked.

The selected repository already has GitHub Pages deployment history. Publishing to its default branch may trigger a Pages rebuild even though this new workflow is manual-only. Existing index.html and LICENSE must remain byte-identical. No publication or runtime action has occurred during preparation.
