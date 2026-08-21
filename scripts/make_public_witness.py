#!/usr/bin/env python3
"""Create a hash-only public witness from an eligible private work manifest."""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

EXPECTED_MANIFEST_SCHEMA = 'public-witness-active-work-watchdog/v3'
EXPECTED_POLICY_ID = 'public-witness-cleared-work-roots/v3'
WITNESS_FORMAT = 'public-witness/v2'
GENERIC_SCOPE = 'selected private/local active-work witness manifest'
PUBLIC_TRACKED_PATH_ALLOWLIST = (
    '.gitignore', '.github/**', 'README.md', 'requirements-ci.txt',
    'chain/**', 'scripts/**', 'templates/**', 'tests/**', 'witnesses/**',
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolved(value: Any) -> Path:
    return Path(str(value)).expanduser().resolve()


def _is_same_or_below(path: Path, prefix: Path) -> bool:
    return path == prefix or prefix in path.parents


def _root_descriptor(root: dict[str, Any]) -> dict[str, Any]:
    mode = str(root.get('mode', ''))
    descriptor: dict[str, Any] = {
        'id': str(root.get('id', '')),
        'path': str(_resolved(root.get('path', ''))),
        'mode': mode,
        'classification': str(root.get('classification', '')),
    }
    if mode == 'git':
        descriptor['include_untracked'] = bool(root.get('include_untracked', False))
        descriptor['tracked_path_allowlist'] = sorted(
            str(item) for item in root.get('tracked_path_allowlist', [])
        )
    elif mode == 'filesystem':
        descriptor['includes'] = sorted(str(item) for item in root.get('includes', []))
        descriptor['excludes'] = sorted(str(item) for item in root.get('excludes', []))
    return descriptor


def validate_source_policy(source_policy: dict[str, Any]) -> None:
    if not isinstance(source_policy, dict) or source_policy.get('policy_id') != EXPECTED_POLICY_ID:
        raise ValueError('unsupported source policy')
    roots = source_policy.get('roots')
    if not isinstance(roots, list) or not roots or not all(isinstance(root, dict) for root in roots):
        raise ValueError('source policy has no cleared work roots')
    denied = [_resolved(item) for item in source_policy.get('denied_root_prefixes', [])]
    forbidden = {_resolved(item) for item in source_policy.get('forbidden_root_paths', [])}
    ids: set[str] = set()
    paths: set[Path] = set()
    for root in roots:
        root_id = str(root.get('id', ''))
        root_path = _resolved(root.get('path', ''))
        mode = str(root.get('mode', ''))
        if not root_id or root_id in ids or root_path in paths:
            raise ValueError('source policy root identity is invalid')
        ids.add(root_id)
        paths.add(root_path)
        if root.get('classification') != 'cleared-work':
            raise ValueError('source policy contains a non-work root')
        if root_path in forbidden:
            raise ValueError('source policy contains a forbidden broad root')
        if any(_is_same_or_below(root_path, prefix) for prefix in denied):
            raise ValueError('source policy contains a denied root')
        if mode not in {'git', 'filesystem', 'file'}:
            raise ValueError('source policy contains an invalid root mode')
        if mode == 'git':
            if bool(root.get('include_untracked', False)):
                raise ValueError('source policy includes untracked Git files')
            if not root.get('tracked_path_allowlist'):
                raise ValueError('Git root has no tracked path allowlist')
        if mode == 'filesystem' and not root.get('includes'):
            raise ValueError('filesystem root has no explicit includes')


def canonical_source_policy(source_policy: dict[str, Any]) -> dict[str, Any]:
    validate_source_policy(source_policy)
    return {
        'policy_id': EXPECTED_POLICY_ID,
        'denied_root_prefixes': sorted(
            str(_resolved(item)) for item in source_policy.get('denied_root_prefixes', [])
        ),
        'forbidden_root_paths': sorted(
            str(_resolved(item)) for item in source_policy.get('forbidden_root_paths', [])
        ),
        'roots': sorted(
            (_root_descriptor(root) for root in source_policy['roots']),
            key=lambda row: row['id'],
        ),
    }


def source_policy_sha256(source_policy: dict[str, Any]) -> str:
    payload = json.dumps(
        canonical_source_policy(source_policy), sort_keys=True, separators=(',', ':')
    ).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()


def source_policy_root_sha256(root: dict[str, Any]) -> str:
    payload = json.dumps(_root_descriptor(root), sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()


def validate_manifest_for_public_hash(manifest: dict[str, Any], source_policy: dict[str, Any]) -> None:
    validate_source_policy(source_policy)
    if manifest.get('schema') != EXPECTED_MANIFEST_SCHEMA:
        raise ValueError('unsupported private manifest schema')

    eligibility = manifest.get('public_hash_eligibility')
    if not isinstance(eligibility, dict) or eligibility.get('eligible') is not True:
        raise ValueError('private manifest is not eligible for a public hash')
    if eligibility.get('policy_id') != EXPECTED_POLICY_ID:
        raise ValueError('private manifest policy id mismatch')
    if eligibility.get('policy_sha256') != source_policy_sha256(source_policy):
        raise ValueError('private manifest policy digest mismatch')
    if int(eligibility.get('disallowed_path_count') or 0) != 0:
        raise ValueError('private manifest reports disallowed paths')

    roots = manifest.get('roots')
    if not isinstance(roots, list) or not all(isinstance(root, dict) for root in roots):
        raise ValueError('private manifest root set is malformed')
    expected = {str(root['id']): root for root in source_policy['roots']}
    actual = {str(root.get('id', '')): root for root in roots}
    if set(expected) != set(actual) or len(actual) != len(roots):
        raise ValueError('private manifest root set does not match cleared work policy')
    if int(eligibility.get('root_count') or -1) != len(expected):
        raise ValueError('private manifest root count mismatch')

    for root_id, policy_root in expected.items():
        row = actual[root_id]
        descriptor = _root_descriptor(policy_root)
        if row.get('source_policy_root_sha256') != source_policy_root_sha256(policy_root):
            raise ValueError('private manifest root policy mismatch')
        if row.get('mode') != descriptor['mode'] or row.get('classification') != 'cleared-work':
            raise ValueError('private manifest root policy mismatch')
        if _resolved(row.get('path', '')) != _resolved(policy_root.get('path', '')):
            raise ValueError('private manifest root policy mismatch')
        if policy_root.get('mode') == 'git' and bool(row.get('include_untracked', True)):
            raise ValueError('private manifest includes untracked Git files')
        if int(row.get('disallowed_path_count') or 0) != 0:
            raise ValueError('private manifest reports disallowed paths')


def disallowed_live_tracked_paths(repo_root: Path) -> list[str]:
    result = subprocess.run(
        ['git', 'ls-files'], cwd=str(repo_root), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    if result.returncode != 0:
        raise ValueError('unable to inspect public repository tracked paths')
    paths = [line.strip().replace('\\', '/') for line in result.stdout.splitlines() if line.strip()]
    return [
        path for path in paths
        if not any(fnmatch.fnmatchcase(path, pattern) for pattern in PUBLIC_TRACKED_PATH_ALLOWLIST)
    ]


def read_last_chain(chain_path: Path):
    if not chain_path.exists() or chain_path.stat().st_size == 0:
        return None
    last = None
    for line in chain_path.read_text(encoding='utf-8').splitlines():
        if line.strip():
            last = json.loads(line)
    return last


def main() -> int:
    parser = argparse.ArgumentParser(description='Create a public witness entry from a private manifest hash.')
    parser.add_argument('--manifest', required=True, help='Private/local manifest; contents are not copied')
    parser.add_argument('--source-policy', required=True, help='Local cleared-work source policy; never published')
    parser.add_argument('--date', default=dt.datetime.now(dt.timezone.utc).date().isoformat())
    parser.add_argument('--scope', default=GENERIC_SCOPE)
    parser.add_argument('--repo-root', default=str(repo_root_from_script()))
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args()

    if args.scope != GENERIC_SCOPE:
        raise SystemExit(
            'Refusing public witness: scope must remain generic; '
            f'use exactly {GENERIC_SCOPE!r}.'
        )

    repo_root = Path(args.repo_root).resolve()
    manifest_path = Path(args.manifest).expanduser().resolve()
    policy_path = Path(args.source_policy).expanduser().resolve()
    if not manifest_path.is_file() or not policy_path.is_file():
        raise SystemExit('Refusing public witness: manifest or source policy is unavailable.')
    for private_path in (manifest_path, policy_path):
        try:
            private_path.relative_to(repo_root)
            raise SystemExit('Refusing public witness: private inputs must remain outside the public repo.')
        except ValueError:
            pass

    try:
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        source_policy = json.loads(policy_path.read_text(encoding='utf-8'))
        validate_manifest_for_public_hash(manifest, source_policy)
        disallowed_live = disallowed_live_tracked_paths(repo_root)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f'Refusing public witness: {exc}') from exc
    if disallowed_live:
        raise SystemExit(
            'Refusing public witness: public repository has '
            f'{len(disallowed_live)} tracked path(s) outside its public allowlist.'
        )

    manifest_sha = sha256_file(manifest_path)
    generator_sha = sha256_file(Path(__file__).resolve())
    witness_path = repo_root / 'witnesses' / args.date[:4] / f'{args.date}.md'
    chain_path = repo_root / 'chain' / 'daily-chain.jsonl'
    if witness_path.exists() and not args.force:
        raise SystemExit(f'witness already exists: {witness_path} (use --force to replace)')
    witness_path.parent.mkdir(parents=True, exist_ok=True)
    chain_path.parent.mkdir(parents=True, exist_ok=True)

    last = read_last_chain(chain_path)
    previous_sha = None if last is None else last.get('witness_sha256')
    previous_display = previous_sha if previous_sha else 'null'
    body = f'''# Witness — {args.date} UTC

hash_algorithm: SHA256
witness_format: {WITNESS_FORMAT}
manifest_schema: {EXPECTED_MANIFEST_SCHEMA}
eligibility_profile: {EXPECTED_POLICY_ID}
generator_sha256: {generator_sha}
scope: {args.scope}
manifest_sha256: {manifest_sha}
previous_witness_sha256: {previous_display}
private_manifest: not published
raw_material: not published

Statement:
This public witness commits to the existence and integrity of a private/local manifest as of this repository history. The underlying material is intentionally not included here.

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
        'witness_format': WITNESS_FORMAT,
        'manifest_schema': EXPECTED_MANIFEST_SCHEMA,
        'eligibility_profile': EXPECTED_POLICY_ID,
        'generator_sha256': generator_sha,
    }
    rows = []
    if chain_path.exists() and chain_path.stat().st_size:
        for line in chain_path.read_text(encoding='utf-8').splitlines():
            if line.strip():
                row = json.loads(line)
                if not (args.force and row.get('date_utc') == args.date):
                    rows.append(row)
    rows.append(entry)
    chain_path.write_text('\n'.join(json.dumps(row, sort_keys=True) for row in rows) + '\n', encoding='utf-8')

    print(f'witness_file={witness_path}')
    print(f'manifest_sha256={manifest_sha}')
    print(f'witness_sha256={witness_sha}')
    print('public_payload=hashes_only')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
