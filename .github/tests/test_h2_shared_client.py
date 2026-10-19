"""H2 uses the reviewed shared bytes and existing absolute PUT budget."""
import ast
import hashlib
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
H2_SHA256 = "d3a0f0ce8482e12404ad0fc8c9228100d863fcab28b986ec3c0b1c165e48cefb"

class SharedH2ClientTests(unittest.TestCase):
    def test_producer_and_publisher_use_exact_reviewed_h2_bytes(self):
        directory = ROOT / ".github/image-publisher"
        producer = directory / "local_artifacts/local_artifact.py"
        publisher = directory / "local_artifact.py"
        self.assertEqual(producer.read_bytes(), publisher.read_bytes())
        self.assertEqual(hashlib.sha256(producer.read_bytes()).hexdigest(), H2_SHA256)

    def test_admission_aliases_existing_io_budget_and_grant_budget_stays_fixed(self):
        for relative in ("local_artifact.py", "local_artifacts/local_artifact.py"):
            with self.subTest(relative=relative):
                tree = ast.parse((ROOT / ".github/image-publisher" / relative).read_text())
                values = {}
                for statement in tree.body:
                    if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                        name = statement.targets[0]
                        if isinstance(name, ast.Name) and name.id in {"PUT_IO_SECONDS", "PUT_WAIT_SECONDS", "GRANT_WAIT_SECONDS", "PUT_RETRY_SECONDS"}:
                            value = statement.value
                            values[name.id] = values[value.id] if isinstance(value, ast.Name) else ast.literal_eval(value)
                self.assertEqual(values, {"PUT_IO_SECONDS": 1800, "PUT_WAIT_SECONDS": 1800, "GRANT_WAIT_SECONDS": 180, "PUT_RETRY_SECONDS": 5})
                assignment = next(s for s in tree.body if isinstance(s, ast.Assign) and isinstance(s.targets[0], ast.Name) and s.targets[0].id == "PUT_WAIT_SECONDS")
                self.assertIsInstance(assignment.value, ast.Name)
                self.assertEqual(assignment.value.id, "PUT_IO_SECONDS")
