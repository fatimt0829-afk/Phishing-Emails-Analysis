import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.analyze_email import analyze_email  # noqa: E402


class EmailAnalyzerTests(unittest.TestCase):
    def test_account_alert_is_high_risk(self):
        result = analyze_email(ROOT / "samples" / "01-account-alert.eml")
        rule_ids = {item["rule_id"] for item in result["findings"]}
        self.assertEqual(result["risk_level"], "high")
        self.assertEqual(result["risk_score"], 100)
        self.assertIn("AUTH-SPF", rule_ids)
        self.assertIn("AUTH-DKIM", rule_ids)
        self.assertIn("AUTH-DMARC", rule_ids)
        self.assertIn("URL-001", rule_ids)

    def test_invoice_requires_escalation_despite_authentication_passes(self):
        result = analyze_email(ROOT / "samples" / "02-invoice-attachment.eml")
        rule_ids = {item["rule_id"] for item in result["findings"]}
        self.assertEqual(result["risk_level"], "high")
        self.assertEqual(result["risk_score"], 70)
        self.assertEqual(result["summary"]["authentication"]["spf"], "pass")
        self.assertIn("HDR-001", rule_ids)
        self.assertIn("URL-001", rule_ids)
        self.assertIn("ATT-001", rule_ids)

    def test_control_message_is_low_risk(self):
        result = analyze_email(ROOT / "samples" / "03-legitimate-control.eml")
        self.assertEqual(result["risk_level"], "low")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()

