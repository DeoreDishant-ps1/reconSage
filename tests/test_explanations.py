import unittest

from reconsage.explanations import (
    explain_finding,
    explain_findings,
)


class TestExplanations(unittest.TestCase):

    def setUp(self):
        self.finding = {
            "service": "MySQL",
            "severity": "MEDIUM",
            "reason": "The database service may be exposed.",
            "evidence": "Port 3306/tcp reported open.",
            "recommendation": "Restrict database access.",
        }

    def test_explains_finding(self):
        result = explain_finding(self.finding)

        self.assertEqual(result["service"], "MySQL")
        self.assertEqual(result["severity"], "MEDIUM")
        self.assertIn("Verify", result["summary"])
        self.assertEqual(result["source"], "rule-based")

    def test_preserves_evidence(self):
        result = explain_finding(self.finding)

        self.assertEqual(
            result["evidence"],
            "Port 3306/tcp reported open.",
        )

    def test_explains_multiple_findings(self):
        results = explain_findings([
            self.finding,
            self.finding,
        ])

        self.assertEqual(len(results), 2)

    def test_handles_missing_fields(self):
        result = explain_finding({})

        self.assertEqual(result["service"], "Unknown service")
        self.assertTrue(result["recommendation"])


if __name__ == "__main__":
    unittest.main()
