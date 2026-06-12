#!/usr/bin/env python3
"""Create a privacy-preserving public witness entry from a private manifest.

This script reads a private manifest file, computes its SHA256 digest, and writes
only that digest plus chain metadata into witnesses/YYYY/YYYY-MM-DD.md.
It never copies manifest contents into the public witness.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[1]


def read_last_chain(chain_path: Path):
    if not chain_path.exists() or chain_path.stat().st_size == 0:
        return None
    last = None
    for line in chain_path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line:
            last = json.loads(line)
    return last


def main() -> int:
    parser = argparse.ArgumentParser(description='Create a public witness entry from a private manifest hash.')
    parser.add_argument('--manifest', required=True, help='Path to private/local manifest. Contents are NOT copied.')
    parser.add_argument('--date', default=dt.datetime.now(dt.timezone.utc).date().isoformat(), help='UTC date, YYYY-MM-DD')
    parser.add_argument('--scope', default='selected private/local research/archive manifest', help='Generic public scope label. Avoid private project names unless cleared.')
    parser.add_argument('--repo-root', default=str(repo_root_from_script()), help='Public witness repo root')
    parser.add_argument('--force', action='store_true', help='Overwrite existing witness for date and replace matching chain row')
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    manifest = Path(args.manifest).expanduser().resolve()
    if not manifest.exists() or not manifest.is_file():
        raise SystemExit(f'private manifest not found: {manifest}')

    # Defensive rail: do not allow the private manifest to live inside the public repo.
    try:
        manifest.relative_to(repo_root)
        raise SystemExit('Refusing: manifest is inside the public repo. Keep private manifests outside the public repo.')
    except ValueError:
        pass

    manifest_sha = sha256_file(manifest)
    year = args.date[:4]
    witness_dir = repo_root / 'witnesses' / year
    witness_path = witness_dir / f'{args.date}.md'
    chain_path = repo_root / 'chain' / 'daily-chain.jsonl'
    witness_dir.mkdir(parents=True, exist_ok=True)
    chain_path.parent.mkdir(parents=True, exist_ok=True)

    last = read_last_chain(chain_path)
    previous_sha = None if last is None else last.get('witness_sha256')

    if witness_path.exists() and not args.force:
        raise SystemExit(f'witness already exists: {witness_path} (use --force to replace)')

    previous_display = previous_sha if previous_sha else 'null'
    body = f'''# Witness — {args.date} UTC

hash_algorithm: SHA256
scope: {args.scope}
manifest_sha256: {manifest_sha}
previous_witness_sha256: {previous_display}
private_manifest: not published
raw_material: not published

Statement:
This public witness commits to the existence and integrity of a private/local manifest as of this repository history. The underlying material may contain private research notes, local paths, archive coordinates, or unpublished artifacts and is intentionally not included here.

Boundary:
This witness is an integrity/timestamp marker, not a public release of the underlying material and not a claim of authorship over every underlying item.
'''
    witness_path.write_text(body, encoding='utf-8')
    witness_sha = sha256_file(witness_path)

    entry = {
        'date_utc': args.date,
        'witness_file': str(witness_path.relative_to(repo_root)),
        'witness_sha256': witness_sha,
        'manifest_sha256': manifest_sha,
        'previous_witness_sha256': previous_sha,
        'scope': args.scope,
    }

    rows = []
    if chain_path.exists() and chain_path.stat().st_size:
        for line in chain_path.read_text(encoding='utf-8').splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if args.force and row.get('date_utc') == args.date:
                continue
            rows.append(row)
    rows.append(entry)
    chain_path.write_text('\n'.join(json.dumps(r, sort_keys=True) for r in rows) + '\n', encoding='utf-8')

    print(f'witness_file={witness_path}')
    print(f'manifest_sha256={manifest_sha}')
    print(f'witness_sha256={witness_sha}')
    print('public_payload=hashes_only')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
