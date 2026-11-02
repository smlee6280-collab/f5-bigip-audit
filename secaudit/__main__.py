"""CLI 진입점.

사용 예:
  python -m secaudit samples -o out
  python -m secaudit configs/ -o out --min-version 17.1.2
  python -m secaudit bigip_base.conf bigip.conf bigip_user.conf --merge --name LTM-01 -o out
"""
import argparse
import sys
from pathlib import Path

from . import audit_text, __version__
from .model import Options, VULN
from .report import write_all

EXTS = {".conf", ".cfg", ".txt", ".scf"}


def collect(paths):
    files = []
    for p in map(Path, paths):
        if p.is_dir():
            files += sorted(f for f in p.rglob("*") if f.suffix.lower() in EXTS)
        elif p.exists():
            files.append(p)
        else:
            print(f"[!] 파일 없음: {p}", file=sys.stderr)
    return files


def main(argv=None):
    ap = argparse.ArgumentParser(prog="secaudit", description="F5 BIG-IP 보안장비 설정 점검(S-01~S-23)")
    ap.add_argument("inputs", nargs="+", help="설정 파일 또는 폴더")
    ap.add_argument("-o", "--out", default="out", help="결과 저장 폴더 (기본: out)")
    ap.add_argument("--merge", action="store_true", help="입력 파일을 한 장비로 합쳐 점검(bigip_base/bigip/bigip_user.conf)")
    ap.add_argument("--name", help="장비명(--merge 또는 단일 파일일 때)")
    ap.add_argument("--session-timeout", type=int, default=600, help="세션 종료 기준(초, 기본 600)")
    ap.add_argument("--log-retention-days", type=int, default=180, help="로컬 로그 보관 기준(일, 기본 180)")
    ap.add_argument("--min-version", help="이 버전 미만이면 S-09 취약 판정 (예: 17.1.2)")
    ap.add_argument("--no-mask", action="store_true", help="Community String 등 민감값 마스킹 해제")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    a = ap.parse_args(argv)

    opts = Options(a.session_timeout, a.log_retention_days, a.min_version, not a.no_mask)
    files = collect(a.inputs)
    if not files:
        ap.error("점검할 설정 파일이 없습니다")

    reports = []
    if a.merge:
        text = "\n".join(f.read_text(encoding="utf-8", errors="replace") for f in files)
        reports.append(audit_text(text, a.name, " + ".join(f.name for f in files), opts))
    else:
        for f in files:
            try:
                name = a.name if (a.name and len(files) == 1) else None
                reports.append(audit_text(f.read_text(encoding="utf-8", errors="replace"), name, f.name, opts))
            except ValueError as e:
                print(f"[!] {e}", file=sys.stderr)
    if not reports:
        return 1

    out = Path(a.out)
    write_all(reports, out)
    print(f"{'장비':<22}{'TMOS':<12}{'양호':>4}{'취약':>4}{'수동':>4}{'해당없음':>6}  준수율")
    for r in reports:
        c = r.counts()
        print(f"{r.name:<22}{r.version:<12}{c['양호']:>4}{c['취약']:>4}{c['수동확인']:>4}"
              f"{c['해당없음']:>6}  {r.score()}%")
        vulns = [x.code for x in r.results if x.status == VULN]
        if vulns:
            print(f"  └ 취약: {', '.join(vulns)}")
    print(f"\n결과: {out}/summary.html, report_*.html, results.csv, results.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
