import tempfile
import unittest
from pathlib import Path

from reconsage.report import generate_report


class TestReport(unittest.TestCase):

    def test_report_contains_findings(self):
        hosts = [{
            "address": "192.168.1.20",
            "hostname": "lab-server",
            "status": "up",
            "ports": [{
                "port": 23,
                "protocol": "tcp",
                "state": "open",
                "service": "telnet",
            }],
        }]

        findings = [{
            "host": "192.168.1.20",
            "port": 23,
            "protocol": "tcp",
            "service": "Telnet",
            "severity": "HIGH",
            "reason": "Telnet traffic is not encrypted.",
            "evidence": "Port 23/tcp reported open.",
            "recommendation": "Disable Telnet and use SSH.",
        }]

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.md"

            result = generate_report(hosts, findings, report_path)
            content = result.read_text(encoding="utf-8")

            self.assertTrue(report_path.exists())
            self.assertIn("Security Assessment Report", content)
            self.assertIn("192.168.1.20", content)
            self.assertIn("Telnet", content)
            self.assertIn("HIGH", content)
            self.assertIn("Disable Telnet and use SSH.", content)

    def test_empty_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.md"

            generate_report([], [], report_path)
            content = report_path.read_text(encoding="utf-8")

            self.assertIn(
            "No findings matched the configured detection rules",
            content
            )


if __name__ == "__main__":
    unittest.main()
