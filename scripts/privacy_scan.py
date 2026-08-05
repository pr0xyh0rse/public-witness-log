#!/usr/bin/env python3
"""Scan tracked public text for local-path and private-token leakage."""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ABSOLUTE_LOCAL_PATHS = re.compile(r"(?:/home/|/Users/|/root/|[A-Za-z]:\\Users\\)")
PRIVATE_METADATA_LABELS = re.compile(
    r"\b(?:project_description|root_count|root_name|private_filename|"
    r"daily_(?:change_)?summary|work_label)\s*[:=]",
    re.IGNORECASE,
)
BINARY_PUBLIC_SUFFIXES = {".ots"}
DISCLOSURE_SURFACES = ("README.md", "chain/", "templates/", "witnesses/")


def tracked_files(repo_root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip())
    paths: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        relative = Path(raw.decode("utf-8", errors="strict"))
        candidate = (repo_root / relative).resolve(strict=True)
        candidate.relative_to(repo_root)
        paths.append(candidate)
    return paths


def load_private_tokens(path: Path | None, repo_root: Path) -> list[str]:
    if path is None:
        return []
    resolved = path.expanduser().resolve(strict=True)
    try:
        resolved.relative_to(repo_root)
    except ValueError:
        pass
    else:
        raise ValueError("forbidden-token file must remain outside the public repository")
    tokens: list[str] = []
    for line in resolved.read_text(encoding="utf-8").splitlines():
        token = line.strip()
        if not token or token.startswith("#"):
            continue
        if len(token) < 4:
            raise ValueError("private tokens must contain at least four characters")
        tokens.append(token)
    return tokens


def scan(repo_root: Path, tokens: list[str]) -> tuple[list[str], int]:
    errors: list[str] = []
    scanned = 0
    for path in tracked_files(repo_root):
        if path.suffix.lower() in BINARY_PUBLIC_SUFFIXES:
            continue
        relative = path.relative_to(repo_root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"{relative}: unexpected non-UTF-8 tracked public file")
            continue
        scanned += 1
        is_disclosure_surface = any(
            relative == surface or relative.startswith(surface)
            for surface in DISCLOSURE_SURFACES
        )
        for lineno, line in enumerate(text.splitlines(), 1):
            if is_disclosure_surface and ABSOLUTE_LOCAL_PATHS.search(line):
                errors.append(f"{relative}:{lineno}: absolute local path")
            if is_disclosure_surface and PRIVATE_METADATA_LABELS.search(line):
                errors.append(f"{relative}:{lineno}: descriptive private-metadata label")
            for index, token in enumerate(tokens, 1):
                if token in line:
                    errors.append(f"{relative}:{lineno}: private token #{index}")
    return errors, scanned


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Public witness repository root",
    )
    parser.add_argument(
        "--forbidden-token-file",
        type=Path,
        help="Optional local-only newline-delimited token file; token values are never printed",
    )
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    try:
        tokens = load_private_tokens(args.forbidden_token_file, repo_root)
        errors, scanned = scan(repo_root, tokens)
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        print(f"FAIL: privacy scan setup: {exc}")
        return 1
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print(f"PASS: scanned {scanned} tracked public text files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
