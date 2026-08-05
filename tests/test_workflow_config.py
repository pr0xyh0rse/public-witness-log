from __future__ import annotations

import unittest
from pathlib import Path

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "verify.yml"


class WorkflowConfigTests(unittest.TestCase):
    def test_python_cache_uses_the_actual_lock_input(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("cache-dependency-path: requirements-ci.txt", text)

    def test_actions_use_current_node24_releases(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09", text)
        self.assertIn("actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1", text)


if __name__ == "__main__":
    unittest.main()
