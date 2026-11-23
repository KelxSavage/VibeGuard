import json
import tempfile
import unittest
from pathlib import Path
from scanners.secrets import scan_repository, deduplicate_findings, finding_fingerprint

class ProfileTests(unittest.TestCase):
    def test_production_excludes_test_tree_but_comprehensive_includes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/"src").mkdir(); (root/"tests").mkdir()
            secret='const token = "sk-proj-FAKE_DEMO_KEY_12345678901234567890";'
            (root/"src/app.js").write_text(secret)
            (root/"tests/test.js").write_text(secret)
            prod=scan_repository(root,"production")
            full=scan_repository(root,"comprehensive")
            self.assertEqual(prod["profile"],"production")
            self.assertEqual(full["profile"],"comprehensive")
            self.assertTrue(all("tests" not in (f.get("file") or "") for f in prod["findings"]))
            self.assertTrue(any(any("tests" in (o.get("file") or "") for o in f.get("occurrences", [])) for f in full["findings"]))

    def test_dedup_groups_copies_and_tracks_occurrences(self):
        base={"category":"exposed_credential","title":"Fake key","evidence":"sk-a…xyz","file":"a.py","line":2}
        other={**base,"file":"archive/a.py","line":9}
        result=deduplicate_findings([base,other])
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]["occurrence_count"],2)

    def test_suppression_requires_exact_fingerprint_and_reason_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/"a.js").write_text('const key = "sk-proj-FAKE_DEMO_KEY_12345678901234567890";')
            first=scan_repository(root,"comprehensive")
            fp=first["findings"][0]["fingerprint"]
            cfg=root/"suppressions.json"; cfg.write_text(json.dumps({"suppressions":[{"fingerprint":fp,"reason":"Confirmed dummy fixture","enabled":True}]}))
            result=scan_repository(root,"comprehensive",cfg)
            self.assertEqual(len(result["suppressed_findings"]),1)
            self.assertEqual(result["suppressed_findings"][0]["suppression_reason"],"Confirmed dummy fixture")
            self.assertEqual(result["finding_summary"]["suppressed"],1)

if __name__ == "__main__": unittest.main()
