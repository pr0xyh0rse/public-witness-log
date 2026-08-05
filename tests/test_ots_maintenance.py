from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parents[1]
SCRIPT = REPO_ROOT / "scripts" / "manage_ots.py"


def make_fake_ots(path: Path) -> None:
    path.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            from __future__ import annotations
            import hashlib
            import shutil
            import sys
            from pathlib import Path

            args = sys.argv[1:]
            command = args[0]
            proof = Path(args[-1])
            target = Path(str(proof)[:-4])
            digest = hashlib.sha256(target.read_bytes()).hexdigest()

            if command == "info":
                print(f"File sha256 hash: {digest}")
                if b"BITCOIN" in proof.read_bytes():
                    print("verify BitcoinBlockHeaderAttestation(999999)")
                    print("# Bitcoin block merkle root " + "a" * 64)
                elif b"UNKNOWN" in proof.read_bytes():
                    print("verify UnknownAttestation()")
                else:
                    print("verify PendingAttestation('https://calendar.example')")
                raise SystemExit(0)

            if command == "upgrade":
                if "-n" in args:
                    if b"AVAILABLE" in proof.read_bytes():
                        print("Success! Timestamp is complete")
                    else:
                        print("Calendar pending")
                    raise SystemExit(0)
                shutil.copy2(proof, Path(str(proof) + ".bak"))
                if b"AVAILABLE" in proof.read_bytes():
                    proof.write_bytes(b"BITCOIN")
                    print("Success! Timestamp is complete")
                else:
                    print("Calendar pending")
                raise SystemExit(0)

            raise SystemExit(2)
            """
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)


def add_proof(repo: Path, date: str, marker: bytes) -> Path:
    witness = repo / "witnesses" / date[:4] / f"{date}.md"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text(f"public witness {date}\n", encoding="utf-8")
    proof = Path(str(witness) + ".ots")
    proof.write_bytes(marker)
    return proof


def run_manage(repo: Path, fake_ots: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo-root",
            str(repo),
            "--ots-bin",
            str(fake_ots),
            *args,
        ],
        text=True,
        capture_output=True,
        check=False,
    )


class OtsMaintenanceTests(unittest.TestCase):
    def test_status_checks_proof_commitment_and_attestation_class(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = base / "repo"
            repo.mkdir()
            fake = base / "ots"
            make_fake_ots(fake)
            add_proof(repo, "2026-01-01", b"PENDING")
            add_proof(repo, "2026-01-02", b"BITCOIN")

            result = run_manage(repo, fake, "status")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("proof_count=2", result.stdout)
            self.assertIn("bitcoin_attested=1", result.stdout)
            self.assertIn("pending=1", result.stdout)
            self.assertIn("commitment_mismatch=0", result.stdout)

    def test_check_uses_dry_run_and_does_not_modify_proof(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = base / "repo"
            repo.mkdir()
            fake = base / "ots"
            make_fake_ots(fake)
            proof = add_proof(repo, "2026-01-01", b"AVAILABLE")
            before = proof.read_bytes()

            result = run_manage(repo, fake, "check")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("upgrade_available=1", result.stdout)
            self.assertRegex(result.stdout, r"upgrade_set_sha256=[0-9a-f]{64}")
            self.assertEqual(proof.read_bytes(), before)
            self.assertFalse(Path(str(proof) + ".bak").exists())

    def test_upgrade_preserves_external_backup_and_leaves_no_repo_bak(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = base / "repo"
            backup = base / "backup"
            repo.mkdir()
            fake = base / "ots"
            make_fake_ots(fake)
            proof = add_proof(repo, "2026-01-01", b"AVAILABLE")
            original_sha = hashlib.sha256(proof.read_bytes()).hexdigest()

            result = run_manage(repo, fake, "upgrade", "--backup-dir", str(backup))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("upgraded=1", result.stdout)
            self.assertEqual(proof.read_bytes(), b"BITCOIN")
            self.assertFalse(Path(str(proof) + ".bak").exists())
            backups = list(backup.rglob("*.ots"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(hashlib.sha256(backups[0].read_bytes()).hexdigest(), original_sha)

    def test_help_entrypoint_exists(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_status_rejects_unrecognized_attestation_structure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = base / "repo"
            repo.mkdir()
            fake = base / "ots"
            make_fake_ots(fake)
            add_proof(repo, "2026-01-01", b"UNKNOWN")
            result = run_manage(repo, fake, "status")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unknown=1", result.stdout + result.stderr)

    def test_upgrade_backup_collision_fails_before_any_proof_changes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = base / "repo"
            backup = base / "backup"
            repo.mkdir()
            fake = base / "ots"
            make_fake_ots(fake)
            first = add_proof(repo, "2026-01-01", b"AVAILABLE")
            second = add_proof(repo, "2026-01-02", b"AVAILABLE")
            collision = backup / second.relative_to(repo)
            collision.parent.mkdir(parents=True)
            collision.write_bytes(b"EXISTING")
            result = run_manage(repo, fake, "upgrade", "--backup-dir", str(backup))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(first.read_bytes(), b"AVAILABLE")
            self.assertEqual(second.read_bytes(), b"AVAILABLE")


if __name__ == "__main__":
    unittest.main()
