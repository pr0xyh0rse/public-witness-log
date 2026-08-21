from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_chain.py"
GENERIC_SCOPE = "selected private/local active-work witness manifest"


def witness_text(date: str, manifest_sha: str, previous: str | None, scope: str = GENERIC_SCOPE) -> str:
    return f"""# Witness — {date} UTC

hash_algorithm: SHA256
scope: {scope}
manifest_sha256: {manifest_sha}
previous_witness_sha256: {previous or 'null'}
private_manifest: not published
raw_material: not published

Statement:
This public witness commits to the existence and integrity of a private/local manifest as of this repository history. The underlying material is intentionally not included here.

Boundary:
This witness is an integrity/timestamp marker, not a public release of the underlying material and not a claim of authorship over every underlying item.
"""


def add_entry(repo: Path, date: str, manifest_sha: str, previous: str | None, *, scope: str = GENERIC_SCOPE) -> dict:
    witness = repo / "witnesses" / date[:4] / f"{date}.md"
    witness.parent.mkdir(parents=True, exist_ok=True)
    witness.write_text(witness_text(date, manifest_sha, previous, scope), encoding="utf-8")
    return {
        "date_utc": date,
        "manifest_sha256": manifest_sha,
        "previous_witness_sha256": previous,
        "scope": scope,
        "witness_file": str(witness.relative_to(repo)),
        "witness_sha256": hashlib.sha256(witness.read_bytes()).hexdigest(),
    }


def run_verify(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(repo)],
        text=True,
        capture_output=True,
        check=False,
    )


class VerifyChainHardeningTests(unittest.TestCase):
    def test_valid_legacy_chain_passes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            row = add_entry(repo, "2026-01-01", "1" * 64, None)
            (repo / "chain").mkdir()
            (repo / "chain/daily-chain.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
            result = run_verify(repo)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PASS: verified 1 witness chain entry", result.stdout)

    def test_witness_path_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = base / "repo"
            repo.mkdir()
            outside = base / "outside.md"
            outside.write_text("not a witness\n", encoding="utf-8")
            (repo / "chain").mkdir()
            row = {
                "date_utc": "2026-01-01",
                "manifest_sha256": "1" * 64,
                "previous_witness_sha256": None,
                "scope": GENERIC_SCOPE,
                "witness_file": "../outside.md",
                "witness_sha256": hashlib.sha256(outside.read_bytes()).hexdigest(),
            }
            (repo / "chain/daily-chain.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
            result = run_verify(repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("canonical witness path", result.stdout + result.stderr)

    def test_duplicate_or_non_increasing_dates_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            first = add_entry(repo, "2026-01-02", "1" * 64, None)
            second = add_entry(repo, "2026-01-01", "2" * 64, first["witness_sha256"])
            (repo / "chain").mkdir()
            (repo / "chain/daily-chain.jsonl").write_text(
                json.dumps(first) + "\n" + json.dumps(second) + "\n",
                encoding="utf-8",
            )
            result = run_verify(repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("strictly increasing", result.stdout + result.stderr)

    def test_chain_scope_must_exactly_match_witness_scope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            row = add_entry(repo, "2026-01-01", "1" * 64, None)
            row["scope"] = "different public label"
            (repo / "chain").mkdir()
            (repo / "chain/daily-chain.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
            result = run_verify(repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("scope mismatch", result.stdout + result.stderr)

    def test_invalid_sha256_shape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            row = add_entry(repo, "2026-01-01", "not-a-sha", None)
            (repo / "chain").mkdir()
            (repo / "chain/daily-chain.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
            result = run_verify(repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("manifest_sha256 is not SHA256", result.stdout + result.stderr)

    def test_extra_chain_label_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            row = add_entry(repo, "2026-01-01", "1" * 64, None)
            row["work_label"] = "richer activity description"
            (repo / "chain").mkdir()
            (repo / "chain/daily-chain.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
            result = run_verify(repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unexpected chain fields", result.stdout + result.stderr)

    def test_extra_witness_summary_is_rejected_even_when_hash_matches(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            row = add_entry(repo, "2026-01-01", "1" * 64, None)
            witness = repo / row["witness_file"]
            witness.write_text(
                witness.read_text(encoding="utf-8") + "Daily summary: richer activity description\n",
                encoding="utf-8",
            )
            row["witness_sha256"] = hashlib.sha256(witness.read_bytes()).hexdigest()
            (repo / "chain").mkdir()
            (repo / "chain/daily-chain.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
            result = run_verify(repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fixed public witness body", result.stdout + result.stderr)

    def test_v2_method_identifiers_are_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            row = add_entry(repo, "2026-01-01", "1" * 64, None)
            method = {
                "witness_format": "public-witness/v2",
                "manifest_schema": "unexpected/private-schema",
                "eligibility_profile": "public-witness-cleared-work-roots/v2",
                "generator_sha256": "a" * 64,
            }
            witness = repo / row["witness_file"]
            text = witness.read_text(encoding="utf-8")
            provenance = "".join(f"{key}: {value}\n" for key, value in method.items())
            witness.write_text(
                text.replace("hash_algorithm: SHA256\n", "hash_algorithm: SHA256\n" + provenance),
                encoding="utf-8",
            )
            row.update(method)
            row["witness_sha256"] = hashlib.sha256(witness.read_bytes()).hexdigest()
            (repo / "chain").mkdir()
            (repo / "chain/daily-chain.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
            result = run_verify(repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsupported manifest_schema", result.stdout + result.stderr)

    def test_v3_eligibility_profile_is_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            row = add_entry(repo, "2026-01-01", "1" * 64, None)
            method = {
                "witness_format": "public-witness/v2",
                "manifest_schema": "public-witness-active-work-watchdog/v3",
                "eligibility_profile": "public-witness-cleared-work-roots/v3",
                "generator_sha256": "a" * 64,
            }
            witness = repo / row["witness_file"]
            text = witness.read_text(encoding="utf-8")
            provenance = "".join(f"{key}: {value}\n" for key, value in method.items())
            witness.write_text(
                text.replace("hash_algorithm: SHA256\n", "hash_algorithm: SHA256\n" + provenance),
                encoding="utf-8",
            )
            row.update(method)
            row["witness_sha256"] = hashlib.sha256(witness.read_bytes()).hexdigest()
            (repo / "chain").mkdir()
            (repo / "chain/daily-chain.jsonl").write_text(
                json.dumps(row) + "\n", encoding="utf-8"
            )

            result = run_verify(repo)

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
