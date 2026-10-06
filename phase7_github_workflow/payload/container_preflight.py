"""Read the new container's own limits, await release, then exec fixed fixtures.

This diagnostic revision is prepared only; the predecessor refused a mount.
It preserves the denial policy and reports one bounded refusal observation.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import sys
import time

BASE = Path('/payload')
MEMORY = 268435456
SCRATCH = 16777216
PIDS = 32


# The complete refusal record must fit this smaller ceiling, within the
# unchanged 8192-byte preflight/export limit. Diagnostics never permit release.
MOUNT_REFUSAL_BYTES = 4096


class MountRefusal(ValueError):
    def __init__(self, diagnostic=None):
        super().__init__('OTHER_WRITABLE_MOUNT')
        self.diagnostic = diagnostic


def bounded_text(value, cap):
    return {'value': value[:cap], 'truncated': len(value) > cap,
            'characters_observed': len(value)}


def mount_refusal(point, entry, info, writable):
    # Reuse the exact row/stat/access observations used by the rejecting check.
    # No reread, extra stat/access call, file-content read or process is added.
    diagnostic = None
    try:
        details = {
            'schema': 1,
            'mount_point': bounded_text(point, 256),
            'filesystem_type': bounded_text(entry['type'], 32),
            'mount_flags': bounded_text(','.join(entry['flags']), 128),
            'super_options': bounded_text(','.join(entry['super']), 128),
            'mountinfo_row': bounded_text(entry['row'], 512),
            'lstat': {
                'mode': info.st_mode,
                'mode_text': stat.filemode(info.st_mode),
                'uid': info.st_uid, 'gid': info.st_gid,
                'device': info.st_dev, 'inode': info.st_ino,
                'rdev_major': os.major(info.st_rdev),
                'rdev_minor': os.minor(info.st_rdev),
                'follows_symlinks': False,
            },
            'access': {'mode': 'W_OK', 'effective_ids': True,
                       'follows_symlinks': True, 'writable': writable},
            'atomic_identity_proof': False,
            'scope': 'FIRST_REFUSING_MOUNT_OBSERVATIONS_ONLY',
        }
        trial = {'record': 'PHASE7_CONTAINER_PREFLIGHT', 'status': 'REFUSED',
                 'reason': 'OTHER_WRITABLE_MOUNT', 'fixtures_started': False,
                 'mount_diagnostic': details}
        raw = json.dumps(trial, sort_keys=True, separators=(',', ':'),
                         allow_nan=False).encode()
        if len(raw) + 1 <= MOUNT_REFUSAL_BYTES:
            diagnostic = details
    except Exception:
        # An unavailable or oversized diagnostic retains the original refusal.
        pass
    return MountRefusal(diagnostic)


def need(condition, code):
    if not condition:
        raise ValueError(code)


def bounded(path, cap=65536):
    with Path(path).open('rb') as stream:
        raw = stream.read(cap + 1)
    need(len(raw) <= cap, 'READ_CAP')
    return raw


def emit(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    need(len(raw) <= 8192, 'PREFLIGHT_RECORD_CAP')
    os.set_blocking(1, False)
    end = time.monotonic() + 1.0
    offset = 0
    while offset < len(raw):
        left = end - time.monotonic()
        need(left > 0 and select.select([], [1], [], left)[1], 'PREFLIGHT_EXPORT_TIMEOUT')
        try:
            offset += os.write(1, raw[offset:])
        except BlockingIOError:
            continue


def unescape_mount(value):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)


def mounts():
    result = {}
    for line in bounded('/proc/self/mountinfo').decode('ascii').splitlines():
        fields = line.split()
        split = fields.index('-')
        point = unescape_mount(fields[4])
        need(point not in result, 'DUPLICATE_MOUNTPOINT')
        result[point] = {'flags': fields[5].split(','), 'type': fields[split + 1],
                         'super': fields[split + 3].split(','), 'row': line}
    return result


def size_bytes(text):
    match = re.fullmatch(r'(\d+)([kKmMgG]?)', text)
    need(match is not None, 'TMPFS_SIZE_FORMAT')
    return int(match[1]) * {'': 1, 'k': 1024, 'm': 1024**2, 'g': 1024**3}[match[2].lower()]


def check():
    need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 65534, 'UNPRIVILEGED_ID')
    need(os.getpid() == 1, 'EXPECTED_NAMESPACE_INIT')
    status = dict(line.split(':', 1) for line in bounded('/proc/self/status').decode().splitlines() if ':' in line)
    need(int(status['CapEff'].strip(), 16) == 0 and int(status['CapPrm'].strip(), 16) == 0
         and int(status['CapBnd'].strip(), 16) == 0, 'CAPABILITIES')
    need(status['NoNewPrivs'].strip() == '1' and status['Seccomp'].strip() == '2', 'PROCESS_RESTRICTIONS')
    cgroup = Path('/sys/fs/cgroup')
    need((cgroup / 'cgroup.controllers').is_file(), 'CGROUP_V2_REQUIRED')
    actual = {key: bounded(cgroup / key, 256).decode().strip() for key in
              ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max')}
    need(actual['memory.max'] == str(MEMORY), 'MEMORY_LIMIT')
    need(actual['memory.swap.max'] == '0', 'SWAP_DISABLED')
    need(actual['pids.max'] == str(PIDS), 'PID_LIMIT')
    quota, period = actual['cpu.max'].split()
    need(quota.isdigit() and period.isdigit() and int(quota) == int(period) > 0, 'CPU_QUOTA')
    need(sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo'], 'EXTERNAL_NETWORK')
    layout = mounts()
    need('/' in layout and 'ro' in layout['/']['flags'], 'ROOT_READ_ONLY')
    need('/payload' in layout and 'ro' in layout['/payload']['flags'], 'PAYLOAD_READ_ONLY')
    need('/dev/shm' not in layout, 'NO_SHM_MOUNT')
    tmp = layout.get('/tmp', {})
    need(tmp.get('type') == 'tmpfs' and {'rw', 'nosuid', 'nodev', 'noexec'} <= set(tmp.get('flags', [])), 'TMPFS_FLAGS')
    sizes = [x[5:] for x in tmp.get('super', []) if x.startswith('size=')]
    need(len(sizes) == 1 and size_bytes(sizes[0]) == SCRATCH, 'SCRATCH_LIMIT')
    tmp_stat = Path('/tmp').stat()
    need(tmp_stat.st_uid == tmp_stat.st_gid == 65534 and stat.S_IMODE(tmp_stat.st_mode) == 0o700, 'SCRATCH_OWNER_MODE')
    need(not list(Path('/tmp').iterdir()), 'EMPTY_SCRATCH')
    # Kernel pseudo-filesystems are not ordinary-file scratch. No writable
    # ordinary filesystem/mount is accepted beyond /tmp. The fixed trusted
    # fixtures make no proc/sys/device/mqueue writes; this is not hostile-code
    # containment or a claim of a 16 MiB bound on all kernel state.
    pseudo = {'proc', 'sysfs', 'cgroup2', 'devpts', 'mqueue'}
    masked_nulls = {'/proc/interrupts', '/proc/kcore', '/proc/keys',
                    '/proc/timer_list', '/proc/sched_debug'}
    for point, entry in layout.items():
        if point == '/tmp' or 'ro' in entry['flags'] or entry['type'] in pseudo:
            continue
        # Docker masks these kernel files with the null character device.
        # Its writable device mode is not ordinary-file scratch capacity.
        info = Path(point).lstat()
        if point in masked_nulls and stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(1, 3):
            continue
        writable = os.access(point, os.W_OK, effective_ids=True)
        if writable:
            raise mount_refusal(point, entry, info, writable)
    for entry in Path('/dev').iterdir():
        info = entry.lstat()
        need(not (stat.S_ISREG(info.st_mode) and os.access(entry, os.W_OK, effective_ids=True)), 'DEV_REGULAR_FILE')
    manifest = json.loads(bounded(BASE / 'manifest.json', 16384))
    need(type(manifest) is dict and 1 <= len(manifest) <= 10, 'SOURCE_MANIFEST')
    for name, digest in manifest.items():
        need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./-]+', name) is not None
             and not name.startswith('/') and '..' not in Path(name).parts, 'SOURCE_PATH')
        path = BASE / name
        need(not path.is_symlink() and path.is_file() and path.resolve().is_relative_to(BASE), 'SOURCE_FILE')
        need(hashlib.sha256(bounded(path, 131072)).hexdigest() == digest, 'SOURCE_HASH')
    need({'container_preflight.py', 'qualification_runner.py', 'transport_adapter.py',
          'fake_child.py', 'dependencies/event_adapter.py'} == set(manifest), 'SOURCE_SET')
    return {'record': 'PHASE7_CONTAINER_PREFLIGHT', 'status': 'PASS',
            'limits': actual, 'scratch_bytes': SCRATCH, 'uid': os.geteuid(),
            'pid': os.getpid(), 'interfaces': ['lo'], 'sources_checked': len(manifest),
            'observed_monotonic': time.monotonic(), 'fixtures_started': False,
            'scope': 'TRUSTED_FIXED_SYNTHETIC_WORKLOAD_ONLY'}


def main():
    try:
        record = check()
        emit(record)
        end = time.monotonic() + 5.0
        data = bytearray()
        while not data.endswith(b'\n') and len(data) < 32:
            left = end - time.monotonic()
            need(left > 0 and select.select([0], [], [], left)[0], 'RELEASE_TIMEOUT')
            chunk = os.read(0, 32 - len(data))
            need(bool(chunk), 'RELEASE_EOF')
            data.extend(chunk)
        need(bytes(data) == b'PHASE7_RELEASE\n', 'RELEASE_TOKEN')
        os.close(0)
        fd = os.open('/dev/null', os.O_RDONLY)
        if fd != 0:
            os.dup2(fd, 0)
            os.close(fd)
        os.chdir('/tmp')
        os.execve('/usr/local/bin/python3', ['/usr/local/bin/python3', '-I', '-S', '-B',
                  '/payload/qualification_runner.py'], {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C'})
    except BaseException as error:
        code = str(error) if type(error) in (ValueError, MountRefusal) and re.fullmatch(r'[A-Z_]{1,64}', str(error)) else type(error).__name__
        try:
            refusal = {'record': 'PHASE7_CONTAINER_PREFLIGHT', 'status': 'REFUSED',
                       'reason': code, 'fixtures_started': False}
            if type(error) is MountRefusal and error.diagnostic is not None:
                refusal['mount_diagnostic'] = error.diagnostic
            emit(refusal)
        except BaseException:
            pass
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
