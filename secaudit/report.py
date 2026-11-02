"""점검 결과 출력: 장비별 HTML 보고서, 전체 요약 HTML, CSV, JSON."""
import csv
import html
import json
from datetime import date
from pathlib import Path

from .model import ITEMS, GOOD, VULN, MANUAL, NA, STATUS_ORDER, DeviceReport

CATEGORIES = ["계정관리", "접근관리", "패치관리", "로그관리", "기능관리"]
BADGE = {GOOD: "good", VULN: "vuln", MANUAL: "manual", NA: "na"}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2330;--sub:#5b6474;--line:#e2e5ea;--head:#f0f2f5;
--good:#1f7a4d;--good-bg:#e3f4ea;--vuln:#b42318;--vuln-bg:#fde8e6;--manual:#9a6700;--manual-bg:#fff4d6;
--na:#5b6474;--na-bg:#eef0f3;--accent:#1e3a8a}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1a1e26;--ink:#e6e9ef;--sub:#9aa3b2;
--line:#2c323d;--head:#222833;--good:#5fd39a;--good-bg:#183526;--vuln:#ff8a7a;--vuln-bg:#3b1d1a;
--manual:#f2c45a;--manual-bg:#3a2f12;--na:#9aa3b2;--na-bg:#262b35;--accent:#8fb0ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.55 "Pretendard","Apple SD Gothic Neo","Malgun Gothic","Noto Sans KR",sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 16px 60px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 10px;padding-left:10px;
border-left:4px solid var(--accent)}.sub{color:var(--sub);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-top:16px}
.meta div{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.meta b{display:block;font-size:12px;color:var(--sub);font-weight:500}.meta span{font-size:15px;font-weight:600}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-top:10px}
.stat{border-radius:8px;padding:12px;text-align:center}.stat b{display:block;font-size:24px}
.stat.good{background:var(--good-bg);color:var(--good)}.stat.vuln{background:var(--vuln-bg);color:var(--vuln)}
.stat.manual{background:var(--manual-bg);color:var(--manual)}.stat.na{background:var(--na-bg);color:var(--na)}
.stat.score{background:var(--head);color:var(--ink)}
.tbl{width:100%;overflow-x:auto}table{border-collapse:collapse;width:100%;background:var(--card);font-size:13px}
th,td{border:1px solid var(--line);padding:8px 10px;vertical-align:top;text-align:left}
th{background:var(--head);font-weight:600;white-space:nowrap}td.c{text-align:center;white-space:nowrap}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.badge.good{background:var(--good-bg);color:var(--good)}.badge.vuln{background:var(--vuln-bg);color:var(--vuln)}
.badge.manual{background:var(--manual-bg);color:var(--manual)}.badge.na{background:var(--na-bg);color:var(--na)}
ul.ev{margin:0;padding-left:16px;color:var(--sub);font-family:ui-monospace,Consolas,monospace;font-size:12px;
word-break:break-all}pre{margin:0;white-space:pre-wrap;font-family:ui-monospace,Consolas,monospace;font-size:12px;
background:var(--head);border-radius:6px;padding:8px}.crit{color:var(--sub);font-size:12px;margin-top:4px}
a{color:var(--accent)}.foot{margin-top:28px;color:var(--sub);font-size:12px}
@media print{body{background:#fff}.wrap{max-width:none}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def _e(s):
    return html.escape(str(s or ""))


def _badge(status):
    return f'<span class="badge {BADGE[status]}">{_e(status)}</span>'


def _stats(c, score):
    s = f'<div class="stat score"><b>{score if score is not None else "-"}{"%" if score is not None else ""}</b>보안 준수율</div>'
    for st in STATUS_ORDER:
        s += f'<div class="stat {BADGE[st]}"><b>{c[st]}</b>{st}</div>'
    return f'<div class="stats">{s}</div>'


def _page(title, body):
    return (f'<!doctype html><html lang="ko"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{_e(title)}</title><style>{CSS}</style></head><body><div class="wrap">'
            f'{body}<p class="foot">f5-bigip-audit · 주요정보통신기반시설 보안장비 항목(S-01~S-23) 기준 설정 점검 · '
            f'자동 판정 결과는 진단자 검토 후 확정합니다.</p></div></body></html>')


def device_html(rep: DeviceReport, today: str) -> str:
    c = rep.counts()
    by_cat = {cat: {s: 0 for s in STATUS_ORDER} for cat in CATEGORIES}
    for r in rep.results:
        by_cat[r.item.category][r.status] += 1
    cat_rows = "".join(
        f"<tr><td>{cat}</td>" + "".join(f'<td class="c">{v[s]}</td>' for s in STATUS_ORDER) + "</tr>"
        for cat, v in by_cat.items())
    rows = ""
    for r in rep.results:
        it = r.item
        ev = "".join(f"<li>{_e(x)}</li>" for x in r.evidence)
        rows += (f'<tr><td class="c"><b>{it.code}</b></td><td class="c">{_e(it.category)}</td>'
                 f'<td><b>{_e(it.title)}</b><div class="crit">{_e(it.criteria)}</div></td>'
                 f'<td class="c">{it.importance}</td><td class="c">{_badge(r.status)}</td>'
                 f'<td>{_e(r.detail)}{f"<ul class=ev>{ev}</ul>" if ev else ""}</td>'
                 f'<td>{f"<pre>{_e(r.remedy)}</pre>" if r.remedy and r.status != GOOD else ""}</td></tr>')
    vulns = [r for r in rep.results if r.status == VULN]
    imp_rank = {"상": 0, "중": 1, "하": 2}
    vulns.sort(key=lambda r: (imp_rank[r.item.importance], r.code))
    plan = "".join(
        f'<tr><td class="c">{r.code}</td><td>{_e(r.item.title)}</td><td class="c">{r.item.importance}</td>'
        f'<td>{_e(r.detail)}</td><td><pre>{_e(r.remedy)}</pre></td><td></td><td></td></tr>' for r in vulns)
    manual = [r for r in rep.results if r.status == MANUAL]
    manual_rows = "".join(f'<tr><td class="c">{r.code}</td><td>{_e(r.item.title)}</td><td>{_e(r.detail)}</td>'
                          f'<td>{_e(r.remedy)}</td></tr>' for r in manual)
    body = f"""
<h1>보안장비 취약점 점검 결과 보고서</h1>
<div class="sub">{_e(rep.name)} · {_e(rep.source)}</div>
<div class="meta">
<div><b>장비명</b><span>{_e(rep.name)}</span></div>
<div><b>제조사 / 모델</b><span>{_e(rep.vendor)} {_e(rep.model)}</span></div>
<div><b>OS 버전</b><span>{_e(rep.version or "확인 불가")}</span></div>
<div><b>점검일</b><span>{today}</span></div>
<div><b>점검 기준</b><span>보안장비 S-01~S-23</span></div>
</div>
<h2>1. 점검 결과 요약</h2>{_stats(c, rep.score())}
<p class="sub">보안 준수율 = 양호 / (양호 + 취약). 수동확인·해당없음 항목은 제외.</p>
<div class="tbl"><table><tr><th>영역</th>{''.join(f'<th>{s}</th>' for s in STATUS_ORDER)}</tr>{cat_rows}</table></div>
<h2>2. 취약 항목 조치계획</h2>
{'<div class="tbl"><table><tr><th>코드</th><th>항목</th><th>중요도</th><th>현황</th><th>조치방안</th><th>담당</th><th>완료 예정</th></tr>' + plan + '</table></div>' if vulns else '<p>취약 항목 없음</p>'}
<h2>3. 수동 확인(인터뷰·증적) 필요 항목</h2>
{'<div class="tbl"><table><tr><th>코드</th><th>항목</th><th>사유</th><th>확인 방법</th></tr>' + manual_rows + '</table></div>' if manual else '<p>없음</p>'}
<h2>4. 항목별 상세 결과</h2>
<div class="tbl"><table><tr><th>코드</th><th>영역</th><th>점검 항목 / 판단 기준</th><th>중요도</th><th>결과</th>
<th>현황 및 근거</th><th>조치방안</th></tr>{rows}</table></div>"""
    return _page(f"점검 보고서 - {rep.name}", body)


def summary_html(reports, files, today):
    head = "".join(f"<th>{i.code}</th>" for i in ITEMS)
    rows = ""
    for rep, f in zip(reports, files):
        cells = "".join(f'<td class="c" title="{_e(r.item.title)}: {_e(r.detail)}">'
                        f'<span class="badge {BADGE[r.status]}">{r.status[0]}</span></td>' for r in rep.results)
        c = rep.counts()
        rows += (f'<tr><td><a href="{_e(f)}">{_e(rep.name)}</a><div class="crit">{_e(rep.vendor)} {_e(rep.version)}</div></td>'
                 f'<td class="c">{rep.score() if rep.score() is not None else "-"}%</td>'
                 f'<td class="c">{c[VULN]}</td>{cells}</tr>')
    tot = {s: sum(r.counts()[s] for r in reports) for s in STATUS_ORDER}
    worst = []
    for it in ITEMS:
        n = sum(1 for rep in reports for r in rep.results if r.code == it.code and r.status == VULN)
        if n:
            worst.append((n, it))
    worst.sort(key=lambda x: (-x[0], x[1].code))
    worst_rows = "".join(f'<tr><td class="c">{it.code}</td><td>{_e(it.title)}</td><td class="c">{it.importance}</td>'
                         f'<td class="c">{n} / {len(reports)}</td></tr>' for n, it in worst)
    body = f"""
<h1>보안장비 점검 종합 결과</h1><div class="sub">점검일 {today} · 대상 {len(reports)}대</div>
<h2>1. 전체 요약</h2>{_stats(tot, round(tot[GOOD]*100/(tot[GOOD]+tot[VULN]),1) if tot[GOOD]+tot[VULN] else None)}
<h2>2. 장비별 결과 매트릭스</h2>
<p class="sub">양=양호 · 취=취약 · 수=수동확인 · 해=해당없음 (셀에 마우스를 올리면 현황 표시)</p>
<div class="tbl"><table><tr><th>장비</th><th>준수율</th><th>취약</th>{head}</tr>{rows}</table></div>
<h2>3. 취약 다발 항목</h2>
{'<div class="tbl"><table><tr><th>코드</th><th>항목</th><th>중요도</th><th>취약 장비</th></tr>' + worst_rows + '</table></div>' if worst else '<p>없음</p>'}"""
    return _page("보안장비 점검 종합 결과", body)


def write_all(reports, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    today = date.today().isoformat()
    files = []
    rows = []
    for rep in reports:
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in rep.name)
        fname = f"report_{safe}.html"
        (outdir / fname).write_text(device_html(rep, today), encoding="utf-8")
        files.append(fname)
        for r in rep.results:
            d = r.to_dict()
            rows.append({"장비명": rep.name, "제조사": rep.vendor, "버전": rep.version, "코드": d["code"],
                         "영역": d["category"], "항목": d["title"], "중요도": d["importance"],
                         "결과": d["status"], "현황": d["detail"], "근거": " | ".join(d["evidence"]),
                         "조치방안": d["remedy"].replace("\n", " / ")})
    (outdir / "summary.html").write_text(summary_html(reports, files, today), encoding="utf-8")
    with open(outdir / "results.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    data = [{"device": rep.name, "vendor": rep.vendor, "model": rep.model, "version": rep.version,
             "source": rep.source, "score": rep.score(), "counts": rep.counts(),
             "results": [r.to_dict() for r in rep.results]} for rep in reports]
    (outdir / "results.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return files
