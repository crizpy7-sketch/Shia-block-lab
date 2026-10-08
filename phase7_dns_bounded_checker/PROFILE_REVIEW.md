# Ordinary chrony monitor: conditional profile source review

This source-only review describes the disabled local candidate. It records no
provider observation, workflow execution, target request, admission or live
authorization. The exact input definition is
`phase7_live_adapter/monitor.py:validate_profile`; its actual-fact matching is
`materialize_policy`. The ordinary timing context definition is schema 2 in
`checker/timing.py`. The original generic kernel collector remains unchanged.

## Primary source basis

| Source | Revision or scope | What it supports and what it does not |
| --- | --- | --- |
| [GitHub hosted-runner documentation](https://github.com/github/docs/blob/main/content/actions/concepts/runners/github-hosted-runners.md) | Current official documentation, consulted 2026-10-08 | Runner software updates weekly. The `Set up job` log identifies the exact deployed image. A current README is not evidence about a future ephemeral job. |
| [runner-images Ubuntu source properties](https://github.com/actions/runner-images/blob/e7c7cb8f4227797c6404a4e98c2ad463c2f70f91/images/ubuntu/templates/locals.ubuntu.pkr.hcl) and [toolset](https://github.com/actions/runner-images/blob/e7c7cb8f4227797c6404a4e98c2ad463c2f70f91/images/ubuntu/toolsets/toolset-2404.json) | Repository tree `e7c7cb8f4227797c6404a4e98c2ad463c2f70f91` | Ubuntu24 uses the Canonical Azure `ubuntu-24_04-lts:server` base. This toolset does not explicitly install chrony. Neither file promises an exact effective chrony configuration, future binary hash or selected source. |
| [Ubuntu Noble chrony package](https://packages.ubuntu.com/noble/chrony) and [Noble updates](https://packages.ubuntu.com/noble-updates/chrony) | Published package versions 4.5-1ubuntu4 and 4.5-1ubuntu4.2 when consulted | These support the expected chrony 4.5 package family. They do not establish which package or executable a future daemon uses. |
| [Microsoft Azure Linux time synchronization](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/time-sync) | Current official documentation, consulted 2026-10-08 | Azure hosts obtain time from Microsoft's GPS-backed infrastructure. Hyper-V exposes host time through a PHC with sysfs name `hyperv`; `/dev/ptp_hyperv` avoids device-order ambiguity. The article supplies no numeric accuracy warranty for a particular Linux guest. Its example PHC configuration is not a guarantee about GitHub's image. |
| [chrony 4.5 chronyc manual](https://chrony-project.org/doc/4.5/chronyc.html) | Versioned 4.5 manual | The tracking accuracy expression uses absolute system correction, root dispersion and half root delay, conditional on a correct primary source. Frequency, residual frequency and skew are estimates. Reference time names the processed measurement, and update interval is not a guaranteed validity period. |
| [chrony 4.5 configuration manual](https://chrony-project.org/doc/4.5/chrony.conf.html) | Versioned 4.5 manual | PHC input can require UTC/TAI conversion. Poll 3 means eight seconds and dpoll -2 means quarter-second driver sampling. Linux driver adjustment can reach approximately 100,000 ppm; default maximum slew is 83,333.333 ppm. `maxclockerror` is an assumed stability setting, with a default of 1 ppm. None of these establishes a 500 ppm UTC error-growth bound. |
| [chrony 4.5 sys_timex.c](https://github.com/mlichvar/chrony/blob/4.5/sys_timex.c) | Upstream tag `4.5`, `set_sync_status` | On Linux the function forces its synchronized status false when `rtcsync` is disabled, even when the daemon's own synchronization argument is true. `STA_UNSYNC` can therefore coexist with synchronized chrony tracking. |
| [chrony 4.5 sys_linux.c](https://github.com/mlichvar/chrony/blob/4.5/sys_linux.c) | Upstream tag `4.5`, `set_frequency` and initialization | Linux correction uses both tick and frequency. The generic timex frequency constant of 500 ppm does not bound total Linux adjustment. |

The source pages describe implementation and expected deployment behavior. They
do not attest this job, authenticate local package metadata, prove source UTC
truth or certify the external operating premises below.

## Numerical and operating premises

The profile fixes these exact integer values:

| Profile value | Meaning | Status |
| --- | --- | --- |
| `source_accuracy_bound_ns: 1000000000` | Azure PHC source error, including any timescale-conversion error, is at most one second throughout the covered interval. | External engineering premise; no numeric vendor guarantee was found. |
| `rate_bound_ppb: 1000000` | The modeled system UTC error grows by at most 1,000 ppm throughout the covered interval. | External engineering premise about stable ordinary operation. It is not derived from tracking frequency/skew, `maxclockerror`, a kernel ceiling or default maximum slew. |
| `max_sample_age_ns: 16000000000` | Reject a report whose bounded sample age exceeds sixteen seconds. | Admission filter chosen for an observed eight-second PHC poll. Polling does not guarantee a usable update every eight seconds. |

The three continuity flags are explicit supplied premises:
`no_unaccounted_steps`, `no_restart_or_source_change`, and
`allow_retrospective_projection`. Their value `true` is a claim, not an observed
truth flag. Applicability must include stable timekeeping without an unaccounted
VM pause, unusual hypervisor behavior, leap/timescale disturbance, clock setter
or fast correction that violates the supplied error-growth premise. The default
chrony controller permits much faster slewing; a small observed correction alone
does not prove the premise for the full past or future interval.

The model adds the actual two tracking snapshots, decimal rounding, read
brackets, the one-second source premise and error growth over the entire frozen
interval. It separately combines the result with each applicable externally
reviewed endpoint. Each outward-rounded pair must remain at most five seconds.
A near-perfect tracking report cannot bypass the complete-interval calculation,
freshness checks or the original forty-second owner.

## Actual matching and evidentiary limits

The fixed provider is `NONINTERACTIVE_SUDO_MONITOR`. It uses only reviewed,
noninteractive command tuples for local chronyc version, Unix-socket tracking
and sources, and a zero-argument read-only metadata helper. There is no provider
fallback, forced NTP sample, service activation, configuration edit or clock
adjustment. Six component reservations and the complete DNS/request reservation
share the original phase owner. The wrapper's direct-child reaping and closed
pipes do not prove cleanup of every privileged descendant.

The metadata helper observes one chronyd process and its boot ID, PID/start
ticks, UIDs, executable inode/device/hash, command-line hash and installed
chrony-package version. The daemon may drop privileges. Matching root-owned dpkg
MD5 metadata is a local package association, not authentication of that package
or executable. The helper also checks the Hyper-V device's resolved path, sysfs
clock name and a matching daemon-open device descriptor. Before/after metadata
must agree.

The bounded on-disk configuration graph has fixed permitted directories and
file-count/byte caps. The profile matches exactly one PHC refclock through
`/dev/ptp_hyperv`, poll 3, dpoll -2 and zero offset, with default `PHC0` or a
matching explicit refid. Actual selected-source reports must agree with both
tracking snapshots. This is intentionally narrower than every configuration
shown in Microsoft's documentation; a differing option refuses rather than
being silently reinterpreted. Both actual correction/offset/root-error fields
and frequency/residual/skew fields receive the source-defined observation
filters. Those filters do not prove future stability.

Reading an unchanged on-disk graph does **not** prove the daemon loaded that
graph. `loaded_config_equivalence_assumed: true` and
`no_config_edits_assumed: true` are required external premises. The configuration
digest carried in the legacy field `loaded_config_evidence_sha256` is an
association with the observed disk graph; the field name must not be interpreted
as loaded-configuration verification. `loaded_config_verified`,
`source_truth_verified`, and `kernel_utc_authority_claimed` remain false.

The `rtcsync` implementation explains why a generic kernel flag can be misleading
for this daemon family. This monitor performs zero kernel samples and does not
assert that `rtcsync` is disabled in the running job. It neither relaxes the
unchanged generic kernel sampler nor turns `STA_UNSYNC` into UTC evidence.

Future ephemeral daemon, configuration and source hashes are populated from
actual observations after fixed profile matching. No such hashes are guessed in
the input. The actual-job environment digest is an association, not attestation.
External native/coordinator evidence, review hashes and validity intervals must
still be current, concrete and applicable. Matching their syntax grants no
control authority.

## Nonissued schema-2 example

`PROFILE_EXAMPLE.json` is a complete context shape for a CLOSEOUT phase, with
both endpoint roles. All timestamps deliberately use a stale November 2023
interval; repeated hexadecimal digits are visibly illustrative placeholders.
It is not tied to an ordinary request, current job, native observation or actual
review. It cannot be dispatched or treated as a live candidate input.

To form a real context, independently establish the applicable native and
coordinator endpoints and review identity, set the exact approved commit and
canonical eight-field request digest, and bind the observation lower bound to
that request. Replace every example endpoint digest, bound and interval with
current reviewed inputs. CLOSED/LOGIN requires `coordinator_endpoint: null`;
CLOSEOUT requires its explicit object. A profile validity interval must cover
the entire original observation-to-owner horizon; it must not be renewed from a
later clock read.

All monitor/model outputs remain conditional with `alignment_established=false`,
`execution_authorized=false`, `control_authority=NONE` and
`phase7_acceptance=BLOCKED`. This review supplies neither a source-truth proof nor
the final decision to issue an ordinary gate attempt.
