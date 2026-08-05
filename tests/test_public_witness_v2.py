from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parents[1]
SCRIPT = REPO_ROOT / "scripts" / "make_public_witness.py"
SPEC = importlib.util.spec_from_file_location("make_public_witness", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
mpw = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mpw)

GENERIC_SCOPE = "selected private/local active-work witness manifest"


def prepare_inputs(base: Path) -> tuple[Path, Path, Path]:
    repo = base / "public-repo"
    private = base / "private-inputs"
    repo.mkdir()
    private.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)

    root_file = base / "work-card.md"
    root_file.write_text("synthetic work card\n", encoding="utf-8")
    policy = {
        "policy_id": "public-witness-cleared-work-roots/v2",
        "denied_root_prefixes": [str(base / "private-den")],
        "forbidden_root_paths": [str(base)],
        "roots": [
            {
                "id": "work-card",
                "path": str(root_file),
                "mode": "file",
                "classification": "cleared-work",
            }
        ],
    }
    policy_path = private / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    manifest = {
        "schema": "public-witness-active-work-watchdog/v3",
        "public_hash_eligibility": {
            "eligible": True,
            "policy_id": policy["policy_id"],
            "policy_sha256": mpw.source_policy_sha256(policy),
            "root_count": 1,
            "disallowed_path_count": 0,
        },
        "roots": [
            {
                "id": "work-card",
                "path": str(root_file.resolve()),
                "mode": "file",
                "classification": "cleared-work",
                "source_policy_root_sha256": mpw.source_policy_root_sha256(policy["roots"][0]),
                "disallowed_path_count": 0,
            }
        ],
    }
    manifest_path = private / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return repo, manifest_path, policy_path


def run_generator(repo: Path, manifest: Path, policy: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--manifest",
            str(manifest),
            "--source-policy",
            str(policy),
            "--date",
            "2026-08-06",
            "--repo-root",
            str(repo),
            *extra,
        ],
        text=True,
        capture_output=True,
        check=False,
    )


class PublicWitnessV2Tests(unittest.TestCase):
    def test_new_witness_records_method_provenance_without_source_details(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, manifest, policy = prepare_inputs(Path(td))
            result = run_generator(repo, manifest, policy)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            witness = (repo / "witnesses/2026/2026-08-06.md").read_text(encoding="utf-8")
            generator_sha = hashlib.sha256(SCRIPT.read_bytes()).hexdigest()
            self.assertIn("witness_format: public-witness/v2", witness)
            self.assertIn("manifest_schema: public-witness-active-work-watchdog/v3", witness)
            self.assertIn("eligibility_profile: public-witness-cleared-work-roots/v2", witness)
            self.assertIn(f"generator_sha256: {generator_sha}", witness)
            self.assertIn(f"scope: {GENERIC_SCOPE}", witness)
            self.assertNotIn("work-card", witness)
            self.assertNotIn(str(Path(td)), witness)

            row = json.loads((repo / "chain/daily-chain.jsonl").read_text(encoding="utf-8"))
            self.assertEqual(row["witness_format"], "public-witness/v2")
            self.assertEqual(row["manifest_schema"], "public-witness-active-work-watchdog/v3")
            self.assertEqual(row["eligibility_profile"], "public-witness-cleared-work-roots/v2")
            self.assertEqual(row["generator_sha256"], generator_sha)

    def test_non_generic_scope_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo, manifest, policy = prepare_inputs(Path(td))
            result = run_generator(repo, manifest, policy, "--scope", "specific project activity")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("scope must remain generic", result.stdout + result.stderr)
            self.assertFalse((repo / "witnesses/2026/2026-08-06.md").exists())


if __name__ == "__main__":
    unittest.main()
