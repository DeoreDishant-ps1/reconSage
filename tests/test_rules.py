import unittest

from reconsage.rules import analyze_hosts


class TestSecurityRules(unittest.TestCase):

    def make_host(self, ports):
        return [{
            "address": "192.168.1.20",
            "ports": ports,
        }]

    def make_port(self, number, service, state="open"):
        return {
            "port": number,
            "protocol": "tcp",
            "state": state,
            "service": service,
            "product": None,
            "version": None,
        }

    # Existing detection tests

    def test_detects_telnet(self):
        findings = analyze_hosts(
            self.make_host([self.make_port(23, "telnet")])
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["port"], 23)

    def test_ignores_closed_port(self):
        findings = analyze_hosts(
            self.make_host([
                self.make_port(23, "telnet", "closed")
            ])
        )
        self.assertEqual(findings, [])

    def test_ignores_unlisted_port(self):
        findings = analyze_hosts(
            self.make_host([self.make_port(8080, "http-proxy")])
        )
        self.assertEqual(findings, [])

    def test_ignores_service_mismatch(self):
        findings = analyze_hosts(
            self.make_host([self.make_port(3306, "http")])
        )
        self.assertEqual(findings, [])

    def test_prioritizes_high_severity(self):
        ports = [
            self.make_port(3306, "mysql"),
            self.make_port(23, "telnet"),
        ]
        findings = analyze_hosts(self.make_host(ports))
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["port"], 23)

    def test_handles_empty_hosts(self):
        self.assertEqual(analyze_hosts([]), [])

    def test_includes_version_evidence(self):
        port = self.make_port(3306, "mysql")
        port["product"] = "MySQL"
        port["version"] = "8.0.35"

        findings = analyze_hosts(self.make_host([port]))
        self.assertIn("MySQL 8.0.35", findings[0]["evidence"])

    def test_detects_all_new_service_rules(self):
        service_cases = [
            (25, "smtp"),
            (135, "msrpc"),
            (139, "netbios-ssn"),
            (1433, "ms-sql-s"),
            (5432, "postgresql"),
            (5900, "vnc"),
            (6379, "redis"),
            (27017, "mongodb"),
        ]

        for port_number, service in service_cases:
            with self.subTest(port=port_number, service=service):
                findings = analyze_hosts(
                    self.make_host([
                        self.make_port(port_number, service)
                    ])
                )
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["port"], port_number)

    def test_detects_existing_database_and_remote_access_rules(self):
        service_cases = [
            (21, "ftp"),
            (445, "microsoft-ds"),
            (3306, "mysql"),
            (3389, "ms-wbt-server"),
        ]

        for port_number, service in service_cases:
            with self.subTest(port=port_number, service=service):
                findings = analyze_hosts(
                    self.make_host([
                        self.make_port(port_number, service)
                    ])
                )
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["port"], port_number)

    def test_ignores_mismatched_new_services(self):
        service_cases = [
            (25, "http"),
            (135, "ssh"),
            (1433, "mysql"),
            (5432, "postgres"),
            (5900, "http"),
            (6379, "redis-cli"),
            (27017, "mongodb-alt"),
        ]

        for port_number, service in service_cases:
            with self.subTest(port=port_number, service=service):
                findings = analyze_hosts(
                    self.make_host([
                        self.make_port(port_number, service)
                    ])
                )
                self.assertEqual(findings, [])

    def test_prioritizes_findings_by_severity(self):
        ports = [
            self.make_port(25, "smtp"),
            self.make_port(3306, "mysql"),
            self.make_port(23, "telnet"),
        ]

        findings = analyze_hosts(self.make_host(ports))
        severities = [finding["severity"] for finding in findings]

        self.assertEqual(severities, ["HIGH", "MEDIUM", "LOW"])

    def test_includes_host_and_recommendation(self):
        findings = analyze_hosts(
            self.make_host([self.make_port(23, "telnet")])
        )

        self.assertEqual(findings[0]["host"], "192.168.1.20")
        self.assertTrue(findings[0]["recommendation"])
        self.assertTrue(findings[0]["reason"])

    # New input validation and edge-case tests

    def test_rejects_invalid_hosts_input(self):
        invalid_inputs = [None, "invalid", 123, {}]

        for invalid_input in invalid_inputs:
            with self.subTest(value=invalid_input):
                self.assertEqual(analyze_hosts(invalid_input), [])

    def test_skips_invalid_host_entries(self):
        hosts = [
            None,
            "invalid host",
            123,
            {
                "address": "192.168.1.20",
                "ports": [self.make_port(23, "telnet")],
            },
        ]

        findings = analyze_hosts(hosts)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["port"], 23)

    def test_skips_invalid_ports_collection(self):
        hosts = [
            {"address": "192.168.1.20", "ports": None},
            {"address": "192.168.1.21", "ports": "invalid"},
            {"address": "192.168.1.22", "ports": 123},
        ]

        self.assertEqual(analyze_hosts(hosts), [])

    def test_skips_invalid_port_numbers(self):
        invalid_numbers = [-1, 0, 65536, True, False, "23", None]

        for number in invalid_numbers:
            with self.subTest(port=number):
                findings = analyze_hosts(
                    self.make_host([
                        self.make_port(number, "telnet")
                    ])
                )
                self.assertEqual(findings, [])

    def test_normalizes_service_name(self):
        findings = analyze_hosts(
            self.make_host([
                self.make_port(21, " FTP ")
            ])
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["service"], "FTP")

    def test_ignores_missing_or_invalid_service_name(self):
        invalid_services = [None, "", 123, False]

        for service in invalid_services:
            with self.subTest(service=service):
                findings = analyze_hosts(
                    self.make_host([
                        self.make_port(3306, service)
                    ])
                )
                self.assertEqual(findings, [])

    def test_handles_missing_ports_field(self):
        hosts = [
            {"address": "192.168.1.20"},
            {"address": "192.168.1.21", "ports": []},
        ]

        self.assertEqual(analyze_hosts(hosts), [])

    def test_handles_missing_product_and_version(self):
        port = self.make_port(3306, "mysql")
        port.pop("product")
        port.pop("version")

        findings = analyze_hosts(self.make_host([port]))

        self.assertEqual(len(findings), 1)
        self.assertNotIn("None", findings[0]["evidence"])

    
    def test_analyzes_multiple_hosts(self):
        hosts = [
            {
                "address": "192.168.1.10",
                "ports": [self.make_port(23, "telnet")],
            },
            {
                "address": "192.168.1.20",
                "ports": [self.make_port(3306, "mysql")],
            },
            {
                "address": "192.168.1.30",
                "ports": [self.make_port(25, "smtp")],
            },
        ]

        findings = analyze_hosts(hosts)

        self.assertEqual(len(findings), 3)

    def test_preserves_correct_host_addresses(self):
        hosts = [
            {
                "address": "192.168.1.10",
                "ports": [self.make_port(23, "telnet")],
            },
            {
                "address": "192.168.1.20",
                "ports": [self.make_port(3306, "mysql")],
            },
        ]

        findings = analyze_hosts(hosts)

        detected_hosts = {
            finding["host"] for finding in findings
        }

        self.assertEqual(
            detected_hosts,
            {"192.168.1.10", "192.168.1.20"}
        )

    def test_prioritizes_findings_across_multiple_hosts(self):
        hosts = [
            {
                "address": "192.168.1.10",
                "ports": [self.make_port(25, "smtp")],
            },
            {
                "address": "192.168.1.20",
                "ports": [self.make_port(3306, "mysql")],
            },
            {
                "address": "192.168.1.30",
                "ports": [self.make_port(23, "telnet")],
            },
        ]

        findings = analyze_hosts(hosts)

        self.assertEqual(
            [finding["severity"] for finding in findings],
            ["HIGH", "MEDIUM", "LOW"]
        )

        self.assertEqual(findings[0]["host"], "192.168.1.30")

    def test_ignores_unmatched_services_across_hosts(self):
        hosts = [
            {
                "address": "192.168.1.10",
                "ports": [self.make_port(22, "ssh")],
            },
            {
                "address": "192.168.1.20",
                "ports": [self.make_port(80, "http")],
            },
            {
                "address": "192.168.1.30",
                "ports": [self.make_port(3306, "mysql")],
            },
        ]

        findings = analyze_hosts(hosts)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["host"], "192.168.1.30")



if __name__ == "__main__":
    unittest.main()
