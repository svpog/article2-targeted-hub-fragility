"""Verify every distributed file against the SHA-256 release manifest."""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    manifest = json.loads((ROOT / 'audit/release_manifest.json').read_text())
    failures = []
    for entry in manifest:
        path = ROOT / entry['path']
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
            failures.append(entry['path'])
    if failures:
        print('Integrity check failed:\n' + '\n'.join(failures), file=sys.stderr)
        return 1
    print(f'PASS: {len(manifest)} distributed files match their SHA-256 hashes.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
