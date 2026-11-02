"""샘플 설정으로 판정 결과를 검증하는 회귀 테스트.  실행: python -m unittest discover -s tests -t ."""
import unittest
from pathlib import Path

from secaudit import audit_text, is_f5, parse_tmsh
from secaudit.model import Options, GOOD, VULN

S = Path(__file__).resolve().parent.parent / "samples"


def run(name, **kw):
    text = (S / name).read_text(encoding="utf-8")
    rep = audit_text(text, None, name, Options(**kw))
    return rep, {r.code: r for r in rep.results}


class TestParser(unittest.TestCase):
    def test_detect(self):
        self.assertTrue(is_f5((S / "f5_ltm01.conf").read_text()))
        self.assertFalse(is_f5("config system global\n set hostname x\nend"))

    def test_version_header(self):
        cfg = parse_tmsh.parse((S / "f5_ltm02_hardened.conf").read_text())
        self.assertEqual(cfg.version, "17.1.2")

    def test_irule_kept_raw(self):
        cfg = parse_tmsh.parse((S / "f5_ltm01.conf").read_text())
        self.assertIn("ltm rule /Common/irule_xff", cfg.raw)
        self.assertEqual(len(cfg.objects("ltm", "virtual")), 3)  # iRule 본문이 트리를 깨지 않음

    def test_list_block(self):
        cfg = parse_tmsh.parse((S / "f5_ltm02_hardened.conf").read_text())
        self.assertEqual(cfg.obj("sys", "sshd").block("allow").flat(), ["10.99.0.0/255.255.255.0"])
        self.assertEqual(cfg.db("systemauth.disablerootlogin"), "true")


class TestChecks(unittest.TestCase):
    def test_vulnerable_sample(self):
        _, r = run("f5_ltm01.conf")
        for code in ("S-01", "S-02", "S-03", "S-04", "S-05", "S-06", "S-07", "S-08", "S-11", "S-13",
                     "S-14", "S-15", "S-16", "S-18", "S-19", "S-21", "S-22", "S-23"):
            self.assertEqual(r[code].status, VULN, code)

    def test_hardened_sample(self):
        rep, r = run("f5_ltm02_hardened.conf")
        self.assertEqual(rep.counts()[VULN], 0)
        self.assertEqual(r["S-12"].status, GOOD)   # iCall UCS 백업 인식

    def test_min_version(self):
        _, r = run("f5_ltm01.conf", min_version="17.1.2")
        self.assertEqual(r["S-09"].status, VULN)
        _, r = run("f5_ltm02_hardened.conf", min_version="17.1.2")
        self.assertEqual(r["S-09"].status, GOOD)

    def test_session_timeout_option(self):
        _, r = run("f5_ltm02_hardened.conf", session_timeout=300)
        self.assertEqual(r["S-08"].status, VULN)    # 600초 설정 → 300초 기준이면 취약

    def test_mask(self):
        _, r = run("f5_ltm01.conf")
        self.assertNotIn('"public"', " ".join(r["S-22"].evidence))
        _, r = run("f5_ltm01.conf", mask=False)
        self.assertIn('"public"', " ".join(r["S-22"].evidence))


if __name__ == "__main__":
    unittest.main()
