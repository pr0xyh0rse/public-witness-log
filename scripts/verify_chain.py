#!/usr/bin/env python3
"""Verify public witness files and the tamper-evident chain index."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GENERIC_SCOPE = "selected private/local active-work witness manifest"
EXPECTED_WITNESS_FORMAT = "public-witness/v2"
EXPECTED_MANIFEST_SCHEMA = "public-witness-active-work-watchdog/v3"
SUPPORTED_ELIGIBILITY_PROFILES = {
    "public-witness-cleared-work-roots/v2",
    "public-witness-cleared-work-roots/v3",
}
METHOD_FIELDS = (
    "witness_format",
    "manifest_schema",
    "eligibility_profile",
    "generator_sha256",
)
LEGACY_CHAIN_FIELDS = {
    "date_utc",
    "manifest_sha256",
    "previous_witness_sha256",
    "scope",
    "witness_file",
    "witness_sha256",
}
LEGACY_WITNESS_FIELDS = {
    "hash_algorithm",
    "scope",
    "manifest_sha256",
    "previous_witness_sha256",
    "private_manifest",
    "raw_material",
}
PUBLIC_SUFFIX = """Statement:
This public witness commits to the existence and integrity of a private/local manifest as of this repository history. The underlying material is intentionally not included here.

Boundary:
This witness is an integrity/timestamp marker, not a public release of the underlying material and not a claim of authorship over every underlying item.
"""
LEGACY_PUBLIC_SUFFIX = """Statement:
This public witness commits to the existence and integrity of a private/local manifest as of this repository history. The underlying material may contain private research notes, local paths, archive coordinates, or unpublished artifacts and is intentionally not included here.

Boundary:
This witness is an integrity/timestamp marker, not a public release of the underlying material and not a claim of authorship over every underlying item.
"""
PUBLIC_SUFFIXES = (PUBLIC_SUFFIX, LEGACY_PUBLIC_SUFFIX)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_witness_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        if line == "Statement:":
            break
        if not line or ": " not in line:
            continue
        key, value = line.split(": ", 1)
        if key in fields:
            raise ValueError(f"duplicate witness field {key}")
        fields[key] = value
    return fields


def _valid_date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return dt.date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _valid_sha(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def verify_repository(repo_root: Path) -> list[str]:
    repo_root = repo_root.resolve()
    chain_path = repo_root / "chain" / "daily-chain.jsonl"
    errors: list[str] = []
    if not chain_path.is_file():
        return ["missing chain/daily-chain.jsonl"]

    rows: list[tuple[int, dict[str, Any]]] = []
    try:
        for lineno, line in enumerate(chain_path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"line {lineno}: invalid JSON: {exc.msg}")
                continue
            if not isinstance(row, dict):
                errors.append(f"line {lineno}: chain row must be an object")
                continue
            rows.append((lineno, row))
    except OSError as exc:
        return [f"unable to read chain: {exc}"]

    if not rows:
        return ["chain contains no entries"]

    previous_sha: str | None = None
    previous_date: str | None = None
    for lineno, row in rows:
        prefix = f"line {lineno}"
        date = row.get("date_utc")
        if not _valid_date(date):
            errors.append(f"{prefix}: invalid UTC date")
            continue
        assert isinstance(date, str)
        if previous_date is not None and date <= previous_date:
            errors.append(f"{prefix}: dates must be unique and strictly increasing")
        previous_date = date

        manifest_sha = row.get("manifest_sha256")
        witness_sha = row.get("witness_sha256")
        if not _valid_sha(manifest_sha):
            errors.append(f"{prefix}: manifest_sha256 is not SHA256")
        if not _valid_sha(witness_sha):
            errors.append(f"{prefix}: witness_sha256 is not SHA256")

        row_previous = row.get("previous_witness_sha256")
        if row_previous is not None and not _valid_sha(row_previous):
            errors.append(f"{prefix}: previous_witness_sha256 is not SHA256 or null")
        if row_previous != previous_sha:
            errors.append(
                f"{prefix}: previous_witness_sha256 mismatch; "
                f"expected {previous_sha!r}, got {row_previous!r}"
            )

        scope = row.get("scope")
        if scope != GENERIC_SCOPE:
            errors.append(f"{prefix}: scope is not the fixed generic scope")

        row_method_fields = {field for field in METHOD_FIELDS if field in row}
        expected_row_fields = LEGACY_CHAIN_FIELDS | (set(METHOD_FIELDS) if row_method_fields else set())
        if set(row) != expected_row_fields:
            errors.append(
                f"{prefix}: unexpected chain fields; expected {sorted(expected_row_fields)!r}, "
                f"got {sorted(row)!r}"
            )

        canonical_relative = Path("witnesses") / date[:4] / f"{date}.md"
        witness_file = row.get("witness_file")
        if not isinstance(witness_file, str) or witness_file != canonical_relative.as_posix():
            errors.append(f"{prefix}: witness_file is not the canonical witness path")
            if _valid_sha(witness_sha):
                previous_sha = witness_sha
            continue

        witness_path = repo_root / canonical_relative
        try:
            resolved_witness = witness_path.resolve(strict=True)
            resolved_witness.relative_to(repo_root)
        except (OSError, ValueError):
            errors.append(f"{prefix}: missing or escaping canonical witness path")
            if _valid_sha(witness_sha):
                previous_sha = witness_sha
            continue
        if witness_path.is_symlink() or resolved_witness != witness_path:
            errors.append(f"{prefix}: canonical witness path must be a regular non-symlink file")
            if _valid_sha(witness_sha):
                previous_sha = witness_sha
            continue
        if not witness_path.is_file():
            errors.append(f"{prefix}: canonical witness path is not a regular file")
            if _valid_sha(witness_sha):
                previous_sha = witness_sha
            continue

        actual_witness_sha = sha256_file(witness_path)
        if witness_sha != actual_witness_sha:
            errors.append(
                f"{prefix}: witness sha mismatch; expected {witness_sha!r}, "
                f"got {actual_witness_sha!r}"
            )

        try:
            text = witness_path.read_text(encoding="utf-8")
            fields = parse_witness_fields(text)
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            errors.append(f"{prefix}: invalid witness text: {exc}")
            if _valid_sha(witness_sha):
                previous_sha = witness_sha
            continue

        expected_header = f"# Witness — {date} UTC"
        if not text.startswith(expected_header + "\n"):
            errors.append(f"{prefix}: witness date/header mismatch")
        if fields.get("hash_algorithm") != "SHA256":
            errors.append(f"{prefix}: witness hash_algorithm mismatch")
        if fields.get("scope") != scope:
            errors.append(f"{prefix}: scope mismatch between chain and witness")
        if fields.get("manifest_sha256") != manifest_sha:
            errors.append(f"{prefix}: manifest hash mismatch between chain and witness")
        expected_previous = previous_sha or "null"
        if fields.get("previous_witness_sha256") != expected_previous:
            errors.append(f"{prefix}: previous hash mismatch between chain and witness")
        if fields.get("private_manifest") != "not published":
            errors.append(f"{prefix}: private_manifest boundary is missing")
        if fields.get("raw_material") != "not published":
            errors.append(f"{prefix}: raw_material boundary is missing")
        expected_witness_fields = LEGACY_WITNESS_FIELDS | (
            set(METHOD_FIELDS) if any(field in fields or field in row for field in METHOD_FIELDS) else set()
        )
        if set(fields) != expected_witness_fields:
            errors.append(
                f"{prefix}: unexpected witness fields; expected {sorted(expected_witness_fields)!r}, "
                f"got {sorted(fields)!r}"
            )
        if not any(text.endswith(suffix) for suffix in PUBLIC_SUFFIXES):
            errors.append(f"{prefix}: witness does not use the fixed public witness body (recognized legacy/current forms)")

        method_presence = [field in row or field in fields for field in METHOD_FIELDS]
        if any(method_presence):
            if not all(field in row and field in fields for field in METHOD_FIELDS):
                errors.append(f"{prefix}: method provenance fields are incomplete")
            else:
                for field in METHOD_FIELDS:
                    if fields[field] != row[field]:
                        errors.append(f"{prefix}: {field} mismatch between chain and witness")
                if row.get("witness_format") != EXPECTED_WITNESS_FORMAT:
                    errors.append(f"{prefix}: unsupported witness_format")
                if row.get("manifest_schema") != EXPECTED_MANIFEST_SCHEMA:
                    errors.append(f"{prefix}: unsupported manifest_schema")
                if row.get("eligibility_profile") not in SUPPORTED_ELIGIBILITY_PROFILES:
                    errors.append(f"{prefix}: unsupported eligibility_profile")
                if not _valid_sha(row.get("generator_sha256")):
                    errors.append(f"{prefix}: generator_sha256 is not SHA256")

        if _valid_sha(witness_sha):
            previous_sha = witness_sha

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Public witness repository root",
    )
    args = parser.parse_args()
    repo_root = Path(args.repo_root)
    errors = verify_repository(repo_root)
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1

    chain_path = repo_root / "chain" / "daily-chain.jsonl"
    count = sum(1 for line in chain_path.read_text(encoding="utf-8").splitlines() if line.strip())
    word = "entry" if count == 1 else "entries"
    print(f"PASS: verified {count} witness chain {word}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
