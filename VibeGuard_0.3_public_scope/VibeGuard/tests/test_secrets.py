import tempfile
import unittest
from pathlib import Path
from scanners.secrets import scan_repository

class SecretScannerTests(unittest.TestCase):
    def test_detects_fake_training_secret_and_redacts_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.js").write_text(
                'const key = "sk-proj-FAKE_DEMO_KEY_12345678901234567890";',
                encoding="utf-8"
            )
            result = scan_repository(root)
            self.assertGreaterEqual(len(result["findings"]), 1)
            self.assertNotIn("FAKE_DEMO_KEY_12345678901234567890",
                             result["findings"][0]["evidence"])

if __name__ == "__main__":
    unittest.main()
