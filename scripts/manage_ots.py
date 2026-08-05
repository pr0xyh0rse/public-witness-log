#!/usr/bin/env python3
"""Inspect, dry-run, and safely upgrade public OpenTimestamps proofs."""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

DIGEST_RE = re.compile(r"^File sha256 hash: ([0-9a-f]{64})$", re.MULTILINE)


@dataclass(frozen=True)
class ProofStatus:
    proof: Path
    target: Path
    digest: str | None
    actual_digest: str | None
    bitcoin_attested: bool
    has_pending: bool
    error: str | None = None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def find_proofs(repo_root: Path) -> list[Path]:
    return sorted((repo_root / "witnesses").glob("**/*.md.ots"))


def run_ots(ots_bin: str, args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [ots_bin, *args],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def inspect_proof(proof: Path, ots_bin: str, timeout: int) -> ProofStatus:
    target = Path(str(proof)[:-4])
    if not target.is_file():
        return ProofStatus(proof, target, None, None, False, False, "missing target witness")
    result = run_ots(ots_bin, ["info", str(proof)], timeout)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        return ProofStatus(
            proof, target, None, sha256_file(target), False, False,
            f"ots info exited {result.returncode}: {output.strip()}",
        )
    match = DIGEST_RE.search(output)
    digest = match.group(1) if match else None
    return ProofStatus(
        proof=proof,
        target=target,
        digest=digest,
        actual_digest=sha256_file(target),
        bitcoin_attested="BitcoinBlockHeaderAttestation(" in output,
        has_pending="PendingAttestation(" in output,
        error=None if digest else "ots info did not report a SHA256 commitment",
    )


def inspect_all(repo_root: Path, ots_bin: str, timeout: int) -> list[ProofStatus]:
    return [inspect_proof(proof, ots_bin, timeout) for proof in find_proofs(repo_root)]


def status_counts(statuses: list[ProofStatus]) -> dict[str, int]:
    return {
        "proof_count": len(statuses),
        "bitcoin_attested": sum(item.bitcoin_attested for item in statuses),
        "pending": sum(not item.bitcoin_attested and item.has_pending for item in statuses),
        "unknown": sum(not item.bitcoin_attested and not item.has_pending for item in statuses),
        "commitment_mismatch": sum(
            item.digest is not None and item.actual_digest is not None and item.digest != item.actual_digest
            for item in statuses
        ),
        "errors": sum(item.error is not None for item in statuses),
    }


def print_counts(counts: dict[str, int]) -> None:
    print(" ".join(f"{key}={value}" for key, value in counts.items()))


def validate_statuses(statuses: list[ProofStatus]) -> list[str]:
    errors: list[str] = []
    for item in statuses:
        if item.error:
            errors.append(f"{item.proof}: {item.error}")
        if not item.bitcoin_attested and not item.has_pending:
            errors.append(f"{item.proof}: no recognized pending or Bitcoin attestation")
        if item.digest is not None and item.actual_digest is not None and item.digest != item.actual_digest:
            errors.append(
                f"{item.proof}: proof commits to {item.digest}, target hashes to {item.actual_digest}"
            )
    return errors


def command_status(args: argparse.Namespace) -> int:
    statuses = inspect_all(args.repo_root, args.ots_bin, args.timeout)
    counts = status_counts(statuses)
    print_counts(counts)
    errors = validate_statuses(statuses)
    for error in errors:
        print(f"FAIL: {error}")
    return 1 if errors or not statuses else 0


def command_check(args: argparse.Namespace) -> int:
    statuses = inspect_all(args.repo_root, args.ots_bin, args.timeout)
    errors = validate_statuses(statuses)
    available = 0
    available_proofs: list[str] = []
    checked = 0
    for item in statuses:
        if item.error or item.digest != item.actual_digest or item.bitcoin_attested:
            continue
        checked += 1
        result = run_ots(args.ots_bin, ["upgrade", "-n", str(item.proof)], args.timeout)
        output = result.stdout + result.stderr
        if result.returncode != 0:
            errors.append(
                f"{item.proof}: dry-run upgrade exited {result.returncode}: {output.strip()}"
            )
            continue
        if re.search(r"Success! Timestamp (?:is )?complete", output):
            available += 1
            available_proofs.append(item.proof.relative_to(args.repo_root).as_posix())
    upgrade_set_sha256 = hashlib.sha256(
        "\n".join(sorted(available_proofs)).encode("utf-8")
    ).hexdigest()
    print(
        f"proof_count={len(statuses)} pending_checked={checked} "
        f"upgrade_available={available} upgrade_set_sha256={upgrade_set_sha256} "
        f"errors={len(errors)}"
    )
    for error in errors:
        print(f"FAIL: {error}")
    return 1 if errors or not statuses else 0


def _atomic_copy(source: Path, destination: Path) -> None:
    temporary = destination.with_name(destination.name + ".tmp")
    shutil.copy2(source, temporary)
    os.replace(temporary, destination)


def command_upgrade(args: argparse.Namespace) -> int:
    backup_dir: Path = args.backup_dir.resolve()
    try:
        backup_dir.relative_to(args.repo_root)
    except ValueError:
        pass
    else:
        print("FAIL: backup directory must be outside the public repository")
        return 1

    statuses = inspect_all(args.repo_root, args.ots_bin, args.timeout)
    errors = validate_statuses(statuses)
    if errors or not statuses:
        for error in errors:
            print(f"FAIL: {error}")
        if not statuses:
            print("FAIL: no .ots proofs found")
        return 1

    candidates = [item for item in statuses if not item.bitcoin_attested]
    unchanged = len(statuses) - len(candidates)
    for item in candidates:
        backup_path = backup_dir / item.proof.relative_to(args.repo_root)
        if backup_path.exists():
            errors.append(f"{item.proof}: refusing to overwrite backup {backup_path}")
    if errors:
        print(
            f"proof_count={len(statuses)} upgraded=0 unchanged={unchanged} "
            f"errors={len(errors)} backup_dir={backup_dir}"
        )
        for error in errors:
            print(f"FAIL: {error}")
        return 1

    prepared: list[tuple[ProofStatus, Path]] = []
    with tempfile.TemporaryDirectory(prefix="public-witness-ots-") as td:
        temp_root = Path(td)
        for item in candidates:
            relative_target = item.target.relative_to(args.repo_root)
            temp_target = temp_root / relative_target
            temp_target.parent.mkdir(parents=True, exist_ok=True)
            temp_proof = Path(str(temp_target) + ".ots")
            shutil.copy2(item.target, temp_target)
            shutil.copy2(item.proof, temp_proof)
            result = run_ots(args.ots_bin, ["upgrade", str(temp_proof)], args.timeout)
            output = result.stdout + result.stderr
            if result.returncode != 0:
                errors.append(
                    f"{item.proof}: upgrade exited {result.returncode}: {output.strip()}"
                )
                continue
            updated = inspect_proof(temp_proof, args.ots_bin, args.timeout)
            if updated.error or updated.digest != updated.actual_digest:
                errors.append(f"{item.proof}: upgraded proof failed commitment inspection")
                continue
            if not updated.bitcoin_attested:
                unchanged += 1
                continue
            prepared.append((item, temp_proof))

        if errors:
            print(
                f"proof_count={len(statuses)} upgraded=0 unchanged={unchanged} "
                f"errors={len(errors)} backup_dir={backup_dir}"
            )
            for error in errors:
                print(f"FAIL: {error}")
            return 1

        for item, _ in prepared:
            backup_path = backup_dir / item.proof.relative_to(args.repo_root)
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with backup_path.open("xb") as handle:
                    handle.write(item.proof.read_bytes())
            except OSError as exc:
                errors.append(f"{item.proof}: unable to preserve backup: {exc}")

        if errors:
            print(
                f"proof_count={len(statuses)} upgraded=0 unchanged={unchanged} "
                f"errors={len(errors)} backup_dir={backup_dir}"
            )
            for error in errors:
                print(f"FAIL: {error}")
            return 1

        for item, temp_proof in prepared:
            _atomic_copy(temp_proof, item.proof)

    upgraded = len(prepared)
    print(
        f"proof_count={len(statuses)} upgraded={upgraded} unchanged={unchanged} "
        f"errors=0 backup_dir={backup_dir}"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Public witness repository root",
    )
    parser.add_argument("--ots-bin", default="ots", help="OpenTimestamps client executable")
    parser.add_argument("--timeout", type=int, default=120, help="Per-command timeout in seconds")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status", help="Inspect proof commitments and attestation classes")
    subparsers.add_parser("check", help="Read-only dry-run query for mature calendar attestations")
    upgrade = subparsers.add_parser("upgrade", help="Upgrade mature proofs via isolated temporary copies")
    upgrade.add_argument("--backup-dir", type=Path, required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    args.repo_root = args.repo_root.resolve()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.command == "status":
        return command_status(args)
    if args.command == "check":
        return command_check(args)
    if args.command == "upgrade":
        return command_upgrade(args)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
