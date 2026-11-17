import os, sys, tempfile, json, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from modules import pcap_reader, analyzer, detector
from utils.make_sample_pcap import write
CFG = json.load(open(os.path.join(ROOT, "src", "config.json")))

class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = os.path.join(tempfile.mkdtemp(), "t.pcap"); write(cls.p)
        cls.df = analyzer.to_dataframe(list(pcap_reader.read_pcap(cls.p)))
        cls.alerts = detector.detect(cls.df, CFG)
    def rules(self, ip): return {a["rule"] for a in self.alerts if a["src_ip"] == ip}
    def test_packet_count(self): self.assertEqual(len(self.df), 553)
    def test_flood_detected(self): self.assertIn("HIGH_PACKET_RATE", self.rules("10.0.0.5"))
    def test_scan_detected(self): self.assertIn("POSSIBLE_PORT_SCAN", self.rules("10.0.0.9"))
    def test_policy(self): self.assertIn("UNEXPECTED_PROTOCOL", self.rules("10.0.0.7"))
    def test_no_false_positive(self):
        for ip in ("10.0.0.2", "10.0.0.3", "10.0.0.4"): self.assertEqual(self.rules(ip), set())
    def test_bad_file(self):
        bad = os.path.join(tempfile.mkdtemp(), "x.pcap"); open(bad, "wb").write(b"junk" * 20)
        with self.assertRaises(ValueError): list(pcap_reader.read_pcap(bad))

if __name__ == "__main__": unittest.main()
