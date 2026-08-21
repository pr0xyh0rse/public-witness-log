from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "make_public_witness.py"
SPEC = importlib.util.spec_from_file_location("make_public_witness", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
mpw = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mpw)


def source_policy(base: Path) -> dict:
    return {
        "policy_id": "public-witness-cleared-work-roots/v3",
        "denied_root_prefixes": [str(base / "private-den")],
        "roots": [
            {
                "id": "work-code",
                "path": str(base / "work-code"),
                "mode": "git",
                "classification": "cleared-work",
                "include_untracked": False,
                "tracked_path_allowlist": ["**"],
            },
            {
                "id": "field-card",
                "path": str(base / "cards" / "field.md"),
                "mode": "file",
                "classification": "cleared-work",
            },
        ],
    }


def manifest_for(policy: dict) -> dict:
    digest = mpw.source_policy_sha256(policy)
    roots = [
        {
            "id": root["id"],
            "path": str(Path(root["path"]).resolve()),
            "mode": root["mode"],
            "classification": "cleared-work",
            "include_untracked": root.get("include_untracked", False),
            "source_policy_root_sha256": mpw.source_policy_root_sha256(root),
            "disallowed_path_count": 0,
        }
        for root in policy["roots"]
    ]
    return {
        "schema": "public-witness-active-work-watchdog/v3",
        "public_hash_eligibility": {
            "eligible": True,
            "policy_id": policy["policy_id"],
            "policy_sha256": digest,
            "root_count": len(roots),
            "disallowed_path_count": 0,
        },
        "roots": roots,
    }


class PublicManifestPolicyTests(unittest.TestCase):
    def test_accepts_exact_cleared_multi_lane_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = source_policy(Path(td))
            mpw.validate_manifest_for_public_hash(manifest_for(policy), policy)

    def test_rejects_extra_private_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = source_policy(Path(td))
            manifest = manifest_for(policy)
            manifest["roots"].append(
                {
                    "id": "private-notes",
                    "path": str(Path(td) / "private-den" / "notes"),
                    "mode": "filesystem",
                    "classification": "cleared-work",
                    "disallowed_path_count": 0,
                }
            )
            with self.assertRaisesRegex(ValueError, "root set"):
                mpw.validate_manifest_for_public_hash(manifest, policy)

    def test_rejects_policy_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = source_policy(Path(td))
            manifest = manifest_for(policy)
            manifest["public_hash_eligibility"]["policy_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "policy digest"):
                mpw.validate_manifest_for_public_hash(manifest, policy)

    def test_rejects_legacy_or_ineligible_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = source_policy(Path(td))
            manifest = manifest_for(policy)
            manifest["schema"] = "public-witness-active-work-watchdog/v2"
            with self.assertRaisesRegex(ValueError, "schema"):
                mpw.validate_manifest_for_public_hash(manifest, policy)
            manifest = manifest_for(policy)
            manifest["public_hash_eligibility"]["eligible"] = False
            with self.assertRaisesRegex(ValueError, "not eligible"):
                mpw.validate_manifest_for_public_hash(manifest, policy)


if __name__ == "__main__":
    unittest.main()
