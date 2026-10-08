"""Build the reviewed production manifest without importing candidate modules.

Run only after production sources and this builder receive source review. Writes
manifest.json and the generated source-binding block in the local workflow.
Does not publish, dispatch, import providers, or perform a network operation.
"""
import ast
import hashlib
import itertools
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


BUILD_ROOT = Path(__file__).resolve().parent
ROOT = BUILD_ROOT.parent if BUILD_ROOT.name == 'review' else BUILD_ROOT
WORKFLOW_ROOT = ROOT if (ROOT / '.github').is_dir() else ROOT.parent
WORKFLOW = WORKFLOW_ROOT / '.github/workflows/phase7-dns-bounded-check.yml'
PACKAGES = frozenset(('checker', 'phase7_live_adapter', 'phase7_clock_sampler',
    'phase7_chrony_capability_probe', 'phase7_chrony_gate_integration',
    'phase7_observed_clock_model', 'phase7_receipt_mapper'))
FILE_CAP = 65536
TOTAL_CAP = 262144
FILE_COUNT_CAP = 64
MANIFEST_CAP = 8192
BEGIN = '          # BEGIN GENERATED SOURCE BINDING\n'
END = '          # END GENERATED SOURCE BINDING\n'
PATH_RE = re.compile(r'[a-z][a-z0-9_]*(?:/[a-z][a-z0-9_]*)*/[a-z_][a-z0-9_]*\.py')


def need(condition, code):
    if not condition:
        raise ValueError(code)


def production_sources():
    """Bounded traversal of the fixed production packages; no test/tool import."""
    result = {}
    for package in sorted(PACKAGES):
        start = ROOT / package
        need(not start.is_symlink() and start.is_dir(), 'PACKAGE_DIRECTORY_INVALID')
        pending = [start]
        while pending:
            directory = pending.pop()
            need(len(directory.relative_to(ROOT).parts) <= 4, 'SOURCE_DEPTH_CAP')
            with os.scandir(directory) as listing:
                entries = list(itertools.islice(listing, 129))
            need(len(entries) <= 128, 'DIRECTORY_ENTRY_CAP')
            for entry in sorted(entries, key=lambda item: item.name):
                need(not entry.is_symlink(), 'SOURCE_SYMLINK_REFUSED')
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    need(re.fullmatch(r'[a-z][a-z0-9_]*', entry.name) is not None,
                         'SOURCE_DIRECTORY_NAME_INVALID')
                    pending.append(path)
                elif path.suffix == '.py':
                    name = path.relative_to(ROOT).as_posix()
                    need(PATH_RE.fullmatch(name) is not None
                         and not path.name.startswith('test_'), 'SOURCE_PATH_INVALID')
                    info = entry.stat(follow_symlinks=False)
                    need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= FILE_CAP,
                         'SOURCE_SIZE_OR_TYPE_INVALID')
                    raw = path.read_bytes()
                    need(len(raw) == info.st_size, 'SOURCE_CHANGED_DURING_READ')
                    result[name] = raw
                    need(len(result) <= FILE_COUNT_CAP, 'SOURCE_COUNT_CAP')
                else:
                    need(path.suffix not in {'.pyc', '.so', '.pyd'},
                         'UNEXPECTED_EXECUTABLE_SOURCE')
    need({'checker/main.py', 'checker/timing.py', 'checker/transport.py'} <= set(result),
         'ORDINARY_TIMING_SOURCE_MISSING')
    need(sum(map(len, result.values())) <= TOTAL_CAP, 'SOURCE_TOTAL_CAP')
    return dict(sorted(result.items()))


def audit_imports(sources):
    """Check explicit local imports and stdlib-only dependencies using AST data."""
    modules = set()
    packages = set(PACKAGES)
    for name in sources:
        path = PurePosixPath(name)
        module = '.'.join(path.with_suffix('').parts)
        if path.name == '__init__.py':
            module = '.'.join(path.parent.parts)
            packages.add(module)
        modules.add(module)
        for parent in path.parents:
            if parent.as_posix() != '.':
                packages.add('.'.join(parent.parts))

    def check_target(target):
        root = target.split('.')[0]
        if root in PACKAGES:
            need(target in modules or target in packages, 'LOCAL_IMPORT_MISSING:' + target)
        else:
            need(root in sys.stdlib_module_names, 'NON_STDLIB_IMPORT:' + target)

    for name, raw in sources.items():
        tree = ast.parse(raw.decode('utf-8'), filename=name)
        path = PurePosixPath(name)
        current_package = list(path.parent.parts)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    check_target(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    need(node.level <= len(current_package), 'RELATIVE_IMPORT_ESCAPES_ROOT')
                    base = current_package[:len(current_package) - node.level + 1]
                    target = '.'.join(base + ([] if node.module is None else node.module.split('.')))
                else:
                    target = node.module or ''
                need(bool(target), 'IMPORT_TARGET_INVALID')
                check_target(target)
                if target in packages:
                    for alias in node.names:
                        need(alias.name != '*', 'NAMESPACE_STAR_IMPORT_REFUSED')
                        check_target(target + '.' + alias.name)
            elif isinstance(node, ast.Call):
                need(not isinstance(node.func, ast.Name) or node.func.id != '__import__',
                     'DYNAMIC_IMPORT_REFUSED')
                need(not isinstance(node.func, ast.Attribute)
                     or not isinstance(node.func.value, ast.Name)
                     or node.func.value.id != 'importlib'
                     or node.func.attr != 'import_module', 'DYNAMIC_IMPORT_REFUSED')


def main():
    sources = production_sources()
    audit_imports(sources)
    document = {'schema': 1,
        'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()},
        'file_bytes': {name: len(raw) for name, raw in sources.items()},
        'total_bytes': sum(map(len, sources.values()))}
    raw = (json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    need(0 < len(raw) <= MANIFEST_CAP, 'MANIFEST_CAP')
    digest = hashlib.sha256(raw).hexdigest()
    need(not WORKFLOW.is_symlink() and WORKFLOW.is_file(), 'WORKFLOW_INVALID')
    text = WORKFLOW.read_text(encoding='utf-8')
    need(text.count(BEGIN) == 1 and text.count(END) == 1, 'WORKFLOW_BINDING_MARKERS_INVALID')
    left, remainder = text.split(BEGIN)
    previous, right = remainder.split(END)
    need(len(previous) <= 16384, 'WORKFLOW_BINDING_BLOCK_CAP')
    block = '          expected_manifest = ' + repr(digest) + '\n'
    block += '          expected_paths = (\n'
    block += ''.join('              ' + repr(name) + ',\n' for name in sources)
    block += '          )\n'
    block += '          expected_total_bytes = ' + str(document['total_bytes']) + '\n'
    generated = left + BEGIN + block + END + right
    # Every validation finishes before either local generated artifact changes.
    (ROOT / 'manifest.json').write_bytes(raw)
    WORKFLOW.write_text(generated, encoding='utf-8')
    print(json.dumps({'status': 'LOCAL_MANIFEST_BUILT', 'production_files': len(sources),
        'production_bytes': document['total_bytes'], 'manifest_bytes': len(raw),
        'manifest_sha256': digest}, sort_keys=True))


if __name__ == '__main__':
    main()
