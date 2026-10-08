"""Zero-argument privileged read-only metadata helper; import performs no reads."""
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

CONFIG = '/etc/chrony/chrony.conf'
DIRECTORIES = {'/etc/chrony/conf.d': '.conf', '/etc/chrony/sources.d': '.sources',
               '/run/chrony-dhcp': '.sources'}
DAEMON = '/usr/sbin/chronyd'
OUTPUT_CAP = 4096
FILE_CAP = 16384
BINARY_CAP = 2097152
STATUS_CAP = 4194304


class FactsError(Exception):
    pass


def require(condition):
    if not condition:
        raise FactsError('FACTS_READ_REFUSED')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def validate_command_line(command):
    require(type(command) is bytes and 0 < len(command) <= 4096 and command.isascii() and command.endswith(b'\0'))
    args = command.rstrip(b'\0').decode('ascii').split('\0')
    require(args and args[0] == DAEMON)
    index, seen = 1, set()
    while index < len(args):
        arg = args[index]
        require(arg[:2] in ('-F', '-f'))
        if len(arg) == 2:
            require(index + 1 < len(args))
            value, index = args[index + 1], index + 2
        else:
            value, index = arg[2:], index + 1
        require(arg[:2] not in seen and value == {'-F': '1', '-f': CONFIG}[arg[:2]])
        seen.add(arg[:2])
    return True


def validate(value):
    keys = {'schema', 'record', 'boot_id', 'pid', 'start_ticks', 'uids', 'daemon_exe', 'hyperv', 'time_namespace',
        'package_version', 'command_line_sha256', 'configuration', 'config_sha256',
        'loaded_config_verified', 'source_truth_verified', 'kernel_utc_authority_claimed'}
    require(type(value) is dict and set(value) == keys and type(value['schema']) is int and value['schema'] == 1
        and value['record'] == 'ORDINARY_CHRONY_MONITOR_FACTS' and len(canonical(value)) < OUTPUT_CAP)
    require(all(type(value[k]) is int and 0 < value[k] < 2**63 for k in ('pid', 'start_ticks')))
    require(type(value['uids']) is list and len(value['uids']) == 4 and all(type(n) is int and 0 <= n < 2**32 for n in value['uids']))
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['boot_id']) is not None)
    require(type(value['time_namespace']) is str and re.fullmatch(r'time:\[[0-9]{1,20}\]', value['time_namespace']) is not None)
    require(all(value[key] is False for key in ('loaded_config_verified', 'source_truth_verified', 'kernel_utc_authority_claimed')))
    daemon, hyperv = value['daemon_exe'], value['hyperv']
    require(type(daemon) is dict and set(daemon) == {'path', 'device', 'inode', 'bytes', 'sha256', 'package_md5_match'}
        and daemon['path'] == DAEMON and daemon['package_md5_match'] is True
        and all(type(daemon[k]) is int and 0 <= daemon[k] < 2**63 for k in ('device', 'inode', 'bytes')))
    require(type(hyperv) is dict and set(hyperv) == {'resolved', 'clock_name', 'device', 'process_open_match'}
        and re.fullmatch(r'/dev/ptp[0-9]{1,3}', hyperv['resolved']) is not None and hyperv['clock_name'] == 'hyperv'
        and type(hyperv['device']) is int and hyperv['device'] >= 0 and hyperv['process_open_match'] is True)
    require(all(re.fullmatch(r'[0-9a-f]{64}', value[k]) is not None for k in ('command_line_sha256', 'config_sha256'))
        and re.fullmatch(r'[0-9a-f]{64}', daemon['sha256']) is not None
        and re.fullmatch(r'4\.5(?:-[A-Za-z0-9.+:~_-]{1,48})?', value['package_version']) is not None)
    config = value['configuration']
    require(type(config) is dict and set(config) == {'files', 'directories', 'configured_sources', 'refclocks'}
        and all(type(config[k]) is list and len(config[k]) <= 8 for k in config)
        and hashlib.sha256(canonical(config)).hexdigest() == value['config_sha256'])
    require(1 <= len(config['files']) <= 8 and config['files'][0][0] == CONFIG)
    for row in config['files']:
        require(type(row) is list and len(row) == 3 and type(row[0]) is str
            and (row[0] == CONFIG or any(re.fullmatch(re.escape(directory) + r'/[A-Za-z0-9_-]{1,64}' + re.escape(suffix), row[0]) for directory, suffix in DIRECTORIES.items()))
            and type(row[1]) is int and 0 <= row[1] <= FILE_CAP and re.fullmatch(r'[0-9a-f]{64}', row[2]) is not None)
    require(sum(row[1] for row in config['files']) <= 65536 and len({row[0] for row in config['files']}) == len(config['files']))
    require(len(config['directories']) <= 3 and {row[0] for row in config['directories']} <= set(DIRECTORIES)
        and all(type(row) is list and len(row) == 2 and type(row[1]) is bool for row in config['directories']))
    require(all(type(row) is list and len(row) == 2 and row[0] in ('server', 'pool', 'peer')
        and type(row[1]) is str and 0 < len(row[1]) <= 255 and row[1].isascii() for row in config['configured_sources']))
    require(all(type(row) is list and 2 <= len(row) <= 31 and all(type(token) is str and 0 < len(token) <= 255
        and token.isascii() and not any(c.isspace() for c in token) for token in row) for row in config['refclocks']))
    return value


def collect_facts():
    """Observe disk/process association, not loaded-config truth or UTC authority."""
    cutoff = time.monotonic_ns() + 700_000_000

    def check():
        require(time.monotonic_ns() < cutoff)

    def read(path, cap, protected=False):
        check()
        if protected:
            for parent in (Path(path), *Path(path).parents):
                info = os.lstat(parent)
                require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            value = stream.read(cap + 1)
            require(len(value) <= cap and (not protected or stat.S_ISREG(info.st_mode)))
        check()
        return value

    require(os.geteuid() == 0)
    boot = read('/proc/sys/kernel/random/boot_id', 64).decode('ascii').strip()
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot) is not None)
    with os.scandir('/proc') as listing:
        entries = list(itertools.islice(listing, 513))
    require(len(entries) <= 512)
    pids = sorted(int(item.name) for item in entries if item.name.isdigit())
    require(len(pids) <= 256)
    found = []
    for pid in pids:
        try:
            if read('/proc/' + str(pid) + '/comm', 32) == b'chronyd\n':
                found.append(pid)
        except FileNotFoundError:
            continue
    require(len(found) == 1)
    pid = found[0]
    prefix = '/proc/' + str(pid)
    require(os.readlink(prefix + '/exe') == DAEMON)
    process = os.stat(prefix + '/exe')
    executable = os.stat(DAEMON)
    require((process.st_dev, process.st_ino) == (executable.st_dev, executable.st_ino))
    binary = read(DAEMON, BINARY_CAP, True)
    binary_hash = hashlib.sha256(binary).hexdigest()
    sums = read('/var/lib/dpkg/info/chrony.md5sums', 65536, True).decode('ascii').splitlines()
    hashes = [line.split()[0] for line in sums if line.split()[1:] == ['usr/sbin/chronyd']]
    require(len(hashes) == 1 and hashlib.md5(binary, usedforsecurity=False).hexdigest() == hashes[0])
    raw_stat = read(prefix + '/stat', 4096).decode('ascii')
    fields = raw_stat[raw_stat.rfind(') ') + 2:].split()
    require(len(fields) >= 20 and fields[19].isdigit())
    uid_lines = [line for line in read(prefix + '/status', 8192).decode('ascii').splitlines() if line.startswith('Uid:')]
    require(len(uid_lines) == 1)
    uids = uid_lines[0].split()[1:]
    require(len(uids) == 4 and all(value.isdigit() and int(value) < 2**32 for value in uids))
    command = read(prefix + '/cmdline', 4096)
    validate_command_line(command)
    namespace = os.readlink('/proc/self/ns/time')
    require(re.fullmatch(r'time:\[[0-9]{1,20}\]', namespace) is not None and os.readlink(prefix + '/ns/time') == namespace)
    package = read('/var/lib/dpkg/status', STATUS_CAP, True).decode('utf-8')
    matches = [part for part in package.split('\n\n') if part.startswith('Package: chrony\n')]
    require(len(matches) == 1 and '\nStatus: install ok installed\n' in '\n' + matches[0] + '\n')
    versions = [line[9:] for line in matches[0].splitlines() if line.startswith('Version: ')]
    require(len(versions) == 1 and re.fullmatch(r'4\.5(?:-[A-Za-z0-9.+:~_-]{1,48})?', versions[0]) is not None)
    device_path = os.path.realpath('/dev/ptp_hyperv')
    require(re.fullmatch(r'/dev/ptp[0-9]{1,3}', device_path) is not None)
    ptp = os.stat(device_path)
    require(stat.S_ISCHR(ptp.st_mode))
    clock_name = read('/sys/class/ptp/' + Path(device_path).name + '/clock_name', 128).decode('ascii').strip()
    require(clock_name == 'hyperv')
    with os.scandir(prefix + '/fd') as listing:
        descriptors = list(itertools.islice(listing, 65))
    require(len(descriptors) <= 64)
    matched = any(os.readlink(item.path) == device_path and os.stat(item.path).st_rdev == ptp.st_rdev
                  for item in descriptors if item.name.isdigit())
    require(matched)
    paths, directories, expanded, seen_files = [CONFIG], [], set(), set()

    def expand(directory):
        check()
        require(directory not in expanded)
        expanded.add(directory)
        if not os.path.exists(directory):
            directories.append([directory, False])
            return
        info = os.lstat(directory)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
        with os.scandir(directory) as listing:
            values = list(itertools.islice(listing, 33))
        require(len(values) <= 32)
        directories.append([directory, True])
        suffix = DIRECTORIES[directory]
        for item in sorted(values, key=lambda entry: entry.name):
            if item.name.endswith(suffix):
                require(re.fullmatch(r'[A-Za-z0-9_-]{1,64}' + re.escape(suffix), item.name) is not None)
                paths.append(directory + '/' + item.name)
    files, sources, refclocks, total = [], [], [], 0
    while paths:
        path = paths.pop(0)
        require(path not in seen_files and len(seen_files) < 8)
        seen_files.add(path)
        raw = read(path, FILE_CAP, True)
        total += len(raw)
        require(total <= 65536)
        files.append([path, len(raw), hashlib.sha256(raw).hexdigest()])
        for line in raw.decode('ascii').splitlines():
            words = line.split('#', 1)[0].split()
            if not words:
                continue
            if words[0] in ('include', 'confdir', 'sourcedir'):
                require(len(words) == 2)
                if words[0] == 'include':
                    matches = [directory for directory, suffix in DIRECTORIES.items() if words[1] == directory + '/*' + suffix]
                    require(len(matches) == 1)
                    expand(matches[0])
                else:
                    require(words[1] in DIRECTORIES and (words[1] == '/etc/chrony/conf.d') == (words[0] == 'confdir'))
                    expand(words[1])
            elif words[0] in ('server', 'pool', 'peer'):
                require(2 <= len(words) <= 32 and 0 < len(words[1]) <= 255)
                sources.append([words[0], words[1]])
                require(len(sources) <= 8)
            elif words[0] == 'refclock':
                require(3 <= len(words) <= 32 and len(refclocks) < 8)
                refclocks.append(words[1:])
    configuration = {'files': files, 'directories': sorted(directories), 'configured_sources': sources, 'refclocks': refclocks}
    check()
    result = {'schema': 1, 'record': 'ORDINARY_CHRONY_MONITOR_FACTS', 'boot_id': boot,
        'pid': pid, 'start_ticks': int(fields[19]), 'uids': list(map(int, uids)), 'time_namespace': namespace,
        'daemon_exe': {'path': DAEMON, 'device': executable.st_dev, 'inode': executable.st_ino,
            'bytes': executable.st_size, 'sha256': binary_hash, 'package_md5_match': True},
        'hyperv': {'resolved': device_path, 'clock_name': clock_name, 'device': ptp.st_rdev, 'process_open_match': True},
        'package_version': versions[0], 'command_line_sha256': hashlib.sha256(command).hexdigest(),
        'configuration': configuration, 'config_sha256': hashlib.sha256(canonical(configuration)).hexdigest(),
        'loaded_config_verified': False, 'source_truth_verified': False,
        'kernel_utc_authority_claimed': False}
    require(len(canonical(result)) + 1 <= OUTPUT_CAP)
    return validate(result)


def main():
    try:
        require(len(sys.argv) == 1)
        result = collect_facts()
    except Exception:
        print('{"code":"FACTS_READ_REFUSED","record":"ORDINARY_CHRONY_MONITOR_FACTS","schema":1,"status":"REFUSED"}')
        return 1
    print(canonical(result).decode('ascii'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
