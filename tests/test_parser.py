import tempfile
import unittest
from pathlib import Path

from reconsage.parser import parse_nmap_xml


class TestNmapParser(unittest.TestCase):

    def test_sample_scan(self):
        sample = (
            Path(__file__).parent.parent
            / "samples"
            / "sample_scan.xml"
        )

        hosts = parse_nmap_xml(sample)

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["address"], "192.168.1.10")
        self.assertEqual(hosts[0]["hostname"], "lab-server")
        self.assertEqual(len(hosts[0]["ports"]), 3)

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            parse_nmap_xml("does_not_exist.xml")

    def test_rejects_wrong_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "wrong.xml"
            path.write_text("<not_nmap/>", encoding="utf-8")

            with self.assertRaises(ValueError):
                parse_nmap_xml(path)

    def test_rejects_malformed_xml(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "malformed.xml"
            path.write_text("<nmaprun>", encoding="utf-8")

            with self.assertRaises(ValueError):
                parse_nmap_xml(path)

    def test_accepts_empty_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "empty.xml"
            path.write_text(
                '<nmaprun scanner="nmap"></nmaprun>',
                encoding="utf-8",
            )

            self.assertEqual(parse_nmap_xml(path), [])

    def test_skips_invalid_port_number(self):
        xml = """
        <nmaprun>
          <host>
            <address addr="192.168.1.5" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="invalid">
                <state state="open"/>
                <service name="mysql"/>
              </port>
              <port protocol="tcp" portid="3306">
                <state state="open"/>
                <service name="mysql"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid_port.xml"
            path.write_text(xml, encoding="utf-8")

            hosts = parse_nmap_xml(path)

            self.assertEqual(len(hosts[0]["ports"]), 1)
            self.assertEqual(hosts[0]["ports"][0]["port"], 3306)


if __name__ == "__main__":
    unittest.main()
