from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parents[1]
SCRIPT = REPO_ROOT / "scripts" / "privacy_scan.py"


def make_repo(base: Path, files: dict[str, str]) -> Path:
    repo = base / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    for relative, content in files.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    return repo


def run_scan(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(repo), *args],
        text=True,
        capture_output=True,
        check=False,
    )


class PrivacyScanTests(unittest.TestCase):
    def test_generic_public_text_passes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = make_repo(Path(td), {"README.md": "Generic integrity witness.\n"})
            result = run_scan(repo)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_absolute_local_path_in_public_text_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = make_repo(
                Path(td),
                {"witnesses/2026/2026-01-01.md": "source: /home/example/private/file.md\n"},
            )
            result = run_scan(repo)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("absolute local path", result.stdout + result.stderr)

    def test_private_token_file_is_local_and_token_is_not_echoed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = make_repo(base, {"README.md": "secret-project-name\n"})
            tokens = base / "private-tokens.txt"
            tokens.write_text("secret-project-name\n", encoding="utf-8")
            result = run_scan(repo, "--forbidden-token-file", str(tokens))
            output = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("private token #1", output)
            self.assertNotIn("secret-project-name", output)


if __name__ == "__main__":
    unittest.main()
