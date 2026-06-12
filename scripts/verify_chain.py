#!/usr/bin/env python3
"""Verify the public witness chain.

Checks that each chain row matches the SHA256 of its witness file, and that each
row points to the previous row's witness SHA256.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    chain_path = repo_root / 'chain' / 'daily-chain.jsonl'
    if not chain_path.exists():
        print('FAIL: missing chain/daily-chain.jsonl')
        return 1

    prev = None
    count = 0
    ok = True
    for lineno, line in enumerate(chain_path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        count += 1
        row = json.loads(line)
        witness_path = repo_root / row['witness_file']
        if not witness_path.exists():
            print(f'FAIL line {lineno}: missing witness file {witness_path}')
            ok = False
            continue
        actual = sha256_file(witness_path)
        if actual != row.get('witness_sha256'):
            print(f'FAIL line {lineno}: witness sha mismatch for {row["witness_file"]}')
            print(f'  expected {row.get("witness_sha256")}')
            print(f'  actual   {actual}')
            ok = False
        if row.get('previous_witness_sha256') != prev:
            print(f'FAIL line {lineno}: previous_witness_sha256 mismatch')
            print(f'  expected {prev}')
            print(f'  actual   {row.get("previous_witness_sha256")}')
            ok = False
        text = witness_path.read_text(encoding='utf-8')
        if row.get('manifest_sha256') not in text:
            print(f'FAIL line {lineno}: manifest hash not present in witness file')
            ok = False
        prev = row.get('witness_sha256')

    if ok:
        word = 'entry' if count == 1 else 'entries'
        print(f'PASS: verified {count} witness chain {word}')
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
