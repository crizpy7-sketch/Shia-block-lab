# Fixed ordinary chrony monitor API

The provider mode is exactly `NONINTERACTIVE_SUDO_MONITOR`. There is no fallback
to direct socket access, a network control socket, a clock setter, or another
provider. The original generic collector, kernel sampler, and observed model are
unchanged. These modules have been authored as local candidates and not executed
by their author.

`collect_private(owner=..., runtime_sha256=..., boundary=None,
required_reserve_ns=...)` returns the existing `collector.CollectionResult`.
`boundary=None` constructs `FixedMonitorBoundary`; a supplied boundary is solely
an offline injection seam. The original owner's exact 40-second monotonic bounds
are observed without creating, extending, or renewing an owner. Six one-second
component reservations precede the unchanged complete network batch reserve.

| Order | Fixed operation | Inner limit | Original-owner reservation |
| --- | --- | ---: | ---: |
| 1 | Direct `/usr/bin/chronyc --version` | Capture guard | 1 second |
| 2 | Noninteractive sudo metadata helper | 0.8 seconds plus 0.1-second kill grace | 1 second |
| 3 | Noninteractive sudo Unix-socket `tracking` | 0.7 seconds plus 0.1-second kill grace | 1 second |
| 4 | Noninteractive sudo Unix-socket `sources` | 0.7 seconds plus 0.1-second kill grace | 1 second |
| 5 | Noninteractive sudo Unix-socket `tracking` | 0.7 seconds plus 0.1-second kill grace | 1 second |
| 6 | Noninteractive sudo metadata helper | 0.8 seconds plus 0.1-second kill grace | 1 second |

Every privileged tuple starts with `/usr/bin/sudo -n -- /usr/bin/timeout
--signal=TERM --kill-after=0.1s`. Chronyc uses only `-n -c -h
/run/chrony/chronyd.sock` followed by the fixed read-only verb. The metadata tuple
runs `/usr/bin/python3 -I -S -B` and the resolved sibling `monitor_facts.py`, with
no helper arguments. Its exact source is part of the workflow's reviewed hash
closure. No shell or caller-controlled command tuple is accepted. Capture output
and combined stderr/stdout are capped at 4,096 bytes. Parent capture has a
0.9-second read interval and at most the remaining 0.1 second for direct-child
closure, all inside the original phase reserve. Successful direct wrapper reaping
and pipe closure do not prove privileged descendant cleanup. A spawn exception
that returns no handle retains original ownership to the same deadline; it cannot
claim that no child existed or that any child was reaped.

A clean nonzero wrapper exit with EOF, reaping and closed pipes can refuse
immediately. An inner timeout (124/137), parent kill, missing EOF, unclosed pipe,
or unreaped wrapper retains that same direct child handle and bounded polling
inside the original owner until its existing 40-second deadline. This uses no
new timer and starts no network batch. It preserves supervision ownership while
privileged descendant cleanup remains unknown. `_capture_frame` has underscore
factory/sleeper seams solely for offline fake-process framing checks; the default
provider wrapper `_capture` passes none of them.

The zero-argument helper performs reads only and starts no subprocess. It requires
effective UID 0 but observes, rather than assumes, chronyd's UID; chronyd may drop
privileges. Within its own 0.7-second read guard it observes one chronyd process,
boot ID, process start ticks, executable identity/hash, command-line hash, chrony
package-version metadata, matching root-owned package MD5 metadata, Hyper-V PHC
device identity and the daemon's open matching device, and bounded on-disk
configuration facts. Parent/helper/daemon time-namespace links must agree;
parent current and time-for-children namespace links must also agree. MD5
equality is observed package association and never
authentication. It checks at
most 512 `/proc` entries and 256 numeric PIDs. Individual proc reads are capped
at 8,192 bytes; the executable at 2,097,152 bytes; dpkg status at 4,194,304 bytes.
This is package-version metadata, not an additional daemon version command.

Configuration reads begin at `/etc/chrony/chrony.conf` and traverse only its
bounded active `include`, `confdir`, and `sourcedir` graph. Allowed expansion is
at most 32 directory entries each in `/etc/chrony/conf.d`,
`/etc/chrony/sources.d`, and `/run/chrony-dhcp`, with the correct matching
`.conf`/`.sources` regular files. Inactive directory files are not used as
effective refclock facts. At most eight
configuration files are read, each at most 16,384 bytes and all at most 65,536
bytes. At most eight configured server/pool/peer entries are retained. Unknown
include/config/source directory paths, symlink or writable protected files,
changed PID/start/boot/binary/config facts, helper output above 4,096 bytes, or any
failed provider refuses. No key file or NTP network response is read.
Daemon arguments allow only the exact binary, optional unique `-F1`/`-F 1`, and
optional unique `-f` with the fixed config path. Unknown flags, positional or
inline directives, other daemon modes and config paths refuse.

The private record is exactly `PRIVATE_ORDINARY_CHRONY_MONITOR`, containing four
chronyc captures, two metadata captures, matching facts, actual selected-source
projection, original owner bounds, client/wrapper identities, and downstream
reserve. `validate_observation(record, runtime)` reconstructs the actual capture
sequence and returns `captures`, `sources`, `source_classification`, `span`,
`binding`, and `facts` for the conditional arithmetic. It does not convert this
record to the old kernel-qualified shape or a synthetic fixture. There are zero
kernel reads and no kernel UTC authority claim.

`materialize_policy(profile, observed, runtime, low_us, high_us)` requires the
`ORDINARY_CHRONY_MONITOR_OPERATING_PROFILE` schema in `monitor.py`, with profile ID
`CANONICAL_NOBLE_CHRONY45_HYPERV_PHC`. It matches actual chrony 4.5 package/binary
association, the Hyper-V `/dev/ptp_hyperv` device and sysfs clock name, and exactly
one configured PHC refclock using that alias or its same observed resolved device,
with poll 3, dpoll -2, zero offset, and matching actual
selected refclock identity. The default PHC0 refid or a matching explicit four-
character refid is supported. The selected report is at most 16 seconds old;
observed correction/offset/root-error fields are at most 100 milliseconds and
frequency/residual/skew fields at most 1,000 ppm. These are observation filters,
not future stability guarantees.

The profile supplies source accuracy of 1 second, error growth of 1,000 ppm, and
sample age of 16 seconds as explicit engineering premises. Those premises are
not vendor guarantees and are not derived from chrony's frequency/skew or its
default maximum slew rate. Applicability and continuity/retrospective premises
remain required. Actual binary, command-line, configuration, and source bindings
are populated from the observed facts; future ephemeral hashes need not be
guessed. The required `loaded_config_equivalence_assumed: true` and
`no_config_edits_assumed: true` are external premises: an unchanged on-disk graph
does not prove what the daemon loaded. The implementation does not assign a
truth or authorization flag to any of these premises.

The exact top-level profile fields are `schema`, `record`, `provider_mode`,
`profile_id`, `valid_from_us`, `valid_until_us`, `source_accuracy_bound_ns`,
`limits`, `config`, `continuity`, and `review_evidence_sha256`. `limits` is exactly
`{"rate_bound_ppb":1000000,"max_sample_age_ns":16000000000}`; `config` contains
the two true external premises above. `continuity` retains the existing model's
three required operating premises, including explicit retrospective projection
when needed.

`validate_profile(profile)` performs the same pure strict schema, exact integer
limits, interval ordering, review digest and true operating-premise checks before
collection. `materialize_policy` reuses it.

`evaluate_observation(record, expected_runtime_sha256=..., profile=...,
valid_from_us=..., valid_until_us=...)` returns the existing `model.ModelResult`.
It uses only `model._policy` and `model._snapshot` after validating the new actual
record. The basis is `ACTUAL_CHRONY_MONITOR_WITH_EXPLICIT_OPERATING_POLICY`.
The operating premises remain unauthenticated and conditional; public and private
results retain `phase7_acceptance: BLOCKED`, `control_authority: NONE`, and false
alignment/execution flags. No live gate, deployment, configuration change, service
action, NTP packet, cleanup attestation, or clock setter is introduced.
