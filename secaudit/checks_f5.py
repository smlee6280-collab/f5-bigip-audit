"""F5 BIG-IP(TMOS) 보안장비 점검 로직 S-01 ~ S-23.

입력: bigip_base.conf + bigip.conf + bigip_user.conf (또는 `tmsh list` / `show running-config` 출력).
tmsh 설정은 기본값을 출력하지 않는 경우가 많아, 객체가 없으면 TMOS 기본값으로 판단한다.
"""
import re
from .model import (GOOD, VULN, MANUAL, NA, Result, Options, mask_secret, ver_tuple,
                    community_weakness, is_generic_account)
from .parse_tmsh import TmshConfig, TNode

EMPTY = TNode()
OPEN_ADDR = {"all", "0.0.0.0/0", "0.0.0.0/0.0.0.0", "::/0", "any"}
EXT_VLAN = re.compile(r"(ext|outside|wan|internet|untrust|public|dmz)", re.I)


def _short(name):
    return name.split("/")[-1] if name else name


def _users(cfg):
    return {_short(n): node for n, node in cfg.objects("auth", "user") if n}


def _role(user):
    pa = user.block("partition-access")
    if pa:
        for _, part in pa.named():
            r = part.getstr("role")
            if r:
                return r
    return user.getstr("role", "no-access")


def _pw_policy(cfg):
    return cfg.obj("auth", "password-policy") or EMPTY


# ---------------------------------------------------------------- 계정관리
def s01(cfg, o):
    users = _users(cfg)
    primary = cfg.db("systemauth.primaryadminuser") or "admin"
    root_off = (cfg.db("systemauth.disablerootlogin") or "false").lower() == "true"
    ev = [f"관리자 계정: {', '.join(users) or '설정에 없음'}",
          f"sys db systemauth.primaryadminuser = {primary}",
          f"sys db systemauth.disablerootlogin = {'true' if root_off else 'false(기본값)'}"]
    problems = []
    if not users:
        return Result("S-01", MANUAL, "auth user 정보 없음 — bigip_user.conf 포함 필요", ev)
    if "admin" in users and primary == "admin":
        problems.append("기본 관리자 계정 'admin' 사용")
    if not root_off:
        problems.append("root 계정 SSH 로그인 허용")
    if problems:
        return Result("S-01", VULN, "; ".join(problems), ev,
                      "신규 관리자 생성 후 기본 계정 비활성화\n"
                      "tmsh modify sys db systemauth.primaryadminuser value <신규계정명>\n"
                      "tmsh modify sys db systemauth.disablerootlogin value true\n"
                      "tmsh save sys config")
    return Result("S-01", GOOD, "기본 계정 admin 변경, root 로그인 차단", ev)


def s02(cfg, o):
    pp = _pw_policy(cfg)
    enf = pp.getstr("policy-enforcement", "disabled")
    length = int(pp.getstr("minimum-length", "6"))
    req = {k: int(pp.getstr(k, "0")) for k in
           ("required-lowercase", "required-uppercase", "required-numeric", "required-special")}
    classes = sum(1 for v in req.values() if v > 0)
    maxdur = int(pp.getstr("max-duration", "99999"))
    ev = [f"auth password-policy > policy-enforcement {enf}, minimum-length {length}",
          f"문자종류 요구 {classes}종, max-duration {maxdur}일"]
    remedy = ("tmsh modify auth password-policy policy-enforcement enabled minimum-length 10 "
              "required-lowercase 1 required-uppercase 1 required-numeric 1 required-special 1 "
              "max-duration 90 password-memory 3")
    if enf != "enabled":
        return Result("S-02", VULN, "비밀번호 정책 강제 미적용(기본값 disabled)", ev, remedy)
    problems = []
    if length < 8:
        problems.append(f"최소 길이 {length}자")
    if classes < 2:
        problems.append(f"문자 조합 {classes}종")
    if problems:
        return Result("S-02", VULN, "복잡도 기준 미달: " + ", ".join(problems), ev, remedy)
    note = "" if maxdur <= 90 else " (변경 주기 미설정 — max-duration 90 권고)"
    return Result("S-02", GOOD, "비밀번호 복잡도 정책 적용" + note, ev)


def s03(cfg, o):
    users = _users(cfg)
    if not users:
        return Result("S-03", MANUAL, "auth user 정보 없음 — bigip_user.conf 포함 필요")
    roles = {n: _role(u) for n, u in users.items()}
    ev = [f"{n}: role {r}" for n, r in roles.items()]
    admins = [n for n, r in roles.items() if r == "admin"]
    if len(users) == 1:
        return Result("S-03", MANUAL, "계정 1개 운영 — 운영자별 권한 분리 여부 확인", ev)
    if len(admins) == len(users):
        return Result("S-03", VULN, f"전체 {len(users)}개 계정이 모두 Administrator 권한", ev,
                      "조회 계정은 guest/auditor, 운영 계정은 operator/manager 역할로 변경\n"
                      "tmsh modify auth user <계정> partition-access modify { all-partitions { role auditor } }")
    return Result("S-03", GOOD, f"권한 분리 적용(admin {len(admins)}개 / 전체 {len(users)}개)", ev)


def s04(cfg, o):
    users = _users(cfg)
    if not users:
        return Result("S-04", MANUAL, "auth user 정보 없음 — bigip_user.conf 포함 필요")
    generic = [n for n in users if is_generic_account(n)]
    ev = [f"계정 목록: {', '.join(users)}"]
    if generic:
        return Result("S-04", VULN, f"공용·테스트·임시 계정 의심: {', '.join(generic)}", ev,
                      "사용 여부 확인 후 tmsh delete auth user <계정>")
    return Result("S-04", MANUAL, "명백한 공용·테스트 계정 없음 — 계정-사용자 매핑표로 1인 1계정 확인 필요", ev)


def s05(cfg, o):
    pp = _pw_policy(cfg)
    mx = int(pp.getstr("max-login-failures", "0"))
    ev = [f"auth password-policy > max-login-failures {mx}" + (" (기본값, 무제한)" if mx == 0 else "")]
    if 0 < mx <= 5:
        return Result("S-05", GOOD, f"로그인 {mx}회 실패 시 잠금", ev)
    return Result("S-05", VULN, "로그인 실패 잠금 미설정" if mx == 0 else f"잠금 임계값 {mx}회(5회 초과)", ev,
                  "tmsh modify auth password-policy max-login-failures 5 lockout-duration 300")


# ---------------------------------------------------------------- 접근관리
def _allow(cfg, svc):
    node = cfg.obj("sys", svc)
    if node is None or node.block("allow") is None:
        return None
    return node.block("allow").flat()


def s06(cfg, o):
    ev, problems = [], []
    for svc, label in (("sshd", "SSH"), ("httpd", "GUI(HTTPS)")):
        allow = _allow(cfg, svc)
        if allow is None:
            ev.append(f"sys {svc} allow 미설정 → 기본값 ALL")
            problems.append(f"{label} 접속 IP 제한 없음(기본값)")
        else:
            ev.append(f"sys {svc} allow {{ {' '.join(allow)} }}")
            if {a.lower() for a in allow} & OPEN_ADDR:
                problems.append(f"{label} 전체 허용")
    if problems:
        return Result("S-06", VULN, "; ".join(problems), ev,
                      "tmsh modify sys sshd allow replace-all-with { <관리망 대역> }\n"
                      "tmsh modify sys httpd allow replace-all-with { <관리망 대역> }")
    return Result("S-06", GOOD, "SSH·GUI 관리 접속이 지정 대역으로 제한됨", ev)


_PROTOS = ["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]


def _enabled_protocols(spec):
    enabled = set()
    for t in re.split(r"[\s:]+", spec.strip()):
        if not t:
            continue
        if t.lower() == "all":
            enabled |= set(_PROTOS)
        elif t[0] in "-!":
            enabled.discard(t[1:])
            if t[1:] == "TLSv1":
                enabled.discard("TLSv1")
        elif t in _PROTOS:
            enabled.add(t)
    return enabled


def s07(cfg, o):
    httpd = cfg.obj("sys", "httpd") or EMPTY
    spec = httpd.getstr("ssl-protocol")
    ev = ["F5 관리 인터페이스는 Telnet/HTTP 평문 접속 미지원(SSH·HTTPS 전용)"]
    if spec is None:
        ev.append("sys httpd ssl-protocol 미설정(버전별 기본값)")
        return Result("S-07", MANUAL, "관리 GUI TLS 버전이 기본값 — TLS 1.0/1.1 비활성 여부 장비에서 확인", ev,
                      'tmsh modify sys httpd ssl-protocol "all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1"')
    ev.append(f'sys httpd ssl-protocol "{spec}"')
    weak = [p for p in ("SSLv3", "TLSv1", "TLSv1.1") if p in _enabled_protocols(spec)]
    if weak:
        return Result("S-07", VULN, f"관리 GUI에서 취약 프로토콜 허용: {', '.join(weak)}", ev,
                      'tmsh modify sys httpd ssl-protocol "all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1"')
    return Result("S-07", GOOD, "SSH·HTTPS(TLS 1.2 이상)만 사용", ev)


def s08(cfg, o):
    lim = o.session_timeout
    sshd = cfg.obj("sys", "sshd") or EMPTY
    httpd = cfg.obj("sys", "httpd") or EMPTY
    ssh_t = int(sshd.getstr("inactivity-timeout", "0"))
    gui_t = int(httpd.getstr("auth-pam-idle-timeout", "1200"))
    ev = [f"sys sshd inactivity-timeout {ssh_t}초" + (" (기본값, 무제한)" if ssh_t == 0 else ""),
          f"sys httpd auth-pam-idle-timeout {gui_t}초" +
          (" (기본값)" if httpd.getstr("auth-pam-idle-timeout") is None else "")]
    problems = []
    if ssh_t == 0 or ssh_t > lim:
        problems.append(f"SSH 유휴 종료 {'없음' if ssh_t == 0 else f'{ssh_t}초'}")
    if gui_t > lim:
        problems.append(f"GUI 유휴 종료 {gui_t}초")
    if problems:
        return Result("S-08", VULN, "; ".join(problems) + f" (기준 {lim}초)", ev,
                      f"tmsh modify sys sshd inactivity-timeout {lim}\n"
                      f"tmsh modify sys httpd auth-pam-idle-timeout {lim}")
    return Result("S-08", GOOD, f"SSH·GUI 유휴 세션 {lim}초 이내 종료", ev)


# ---------------------------------------------------------------- 패치관리
def s09(cfg, o):
    v = cfg.version
    if not v:
        return Result("S-09", MANUAL, "#TMSH-VERSION 헤더가 없어 버전 확인 불가",
                      remedy="tmsh show sys version 으로 확인 후 F5 Security Advisory 대조")
    ev = [f"BIG-IP TMOS v{v}"]
    if o.min_version:
        if ver_tuple(v) < ver_tuple(o.min_version):
            return Result("S-09", VULN, f"TMOS {v} — 기준 버전 {o.min_version} 미만", ev,
                          f"TMOS {o.min_version} 이상 또는 해당 Engineering Hotfix 적용")
        return Result("S-09", GOOD, f"TMOS {v} — 기준 버전 {o.min_version} 이상", ev)
    if ver_tuple(v)[:2] < (15, 1):
        return Result("S-09", VULN, f"TMOS {v} — 소프트웨어 개발 지원 종료 브랜치", ev,
                      "지원 중인 브랜치(17.x 등)로 업그레이드, F5 수명주기 정책 확인")
    return Result("S-09", MANUAL,
                  f"TMOS {v} — F5 Security Advisory(Quarterly Security Notification)와 대조 필요", ev,
                  "my.f5.com 에서 해당 버전 영향 취약점·Hotfix 확인 (--min-version 지정 시 자동 판정)")


# ---------------------------------------------------------------- 로그관리
def _remote_syslog(cfg):
    sl = cfg.obj("sys", "syslog") or EMPTY
    rs = sl.block("remote-servers")
    out = []
    if rs:
        for name, node in rs.named():
            out.append(f"{_short(name)} {node.getstr('host', '?')}:{node.getstr('remote-port', '514')}")
    hsl = [n for n, _ in cfg.objects("sys", "log-config", "destination", "remote-high-speed-log")]
    out += [f"HSL {_short(n)}" for n in hsl if n]
    return out


def s10(cfg, o):
    audit = (cfg.db("config.auditing") or "enable").lower()
    ev = [f"sys db config.auditing = {audit}"]
    if audit == "disable":
        return Result("S-10", VULN, "설정 변경 감사 로그 비활성", ev,
                      "tmsh modify sys db config.auditing value enable")
    vs_log = [(_short(n)) for n, v in cfg.objects("ltm", "virtual") if n and v.block("security-log-profiles")]
    if vs_log:
        ev.append(f"보안 로그 프로파일 적용 VS: {', '.join(vs_log[:10])}")
    return Result("S-10", GOOD, "감사 로그 활성(기본값), 시스템 로그 로컬 기록", ev)


def s11(cfg, o):
    remote = _remote_syslog(cfg)
    if remote:
        return Result("S-11", GOOD, "원격 Syslog로 전송 — 서버 측 보관기간 증적 확인 필요", remote)
    return Result("S-11", VULN, "원격 보관 없음 — 로컬 /var/log 는 logrotate로 순환 삭제되어 장기 보관 불가",
                  ["sys syslog remote-servers 없음"],
                  "tmsh modify sys syslog remote-servers add { syslog1 { host <IP> remote-port 514 } }")


def s12(cfg, o):
    for name, body in cfg.raw.items():
        if "icall script" in name and re.search(r"save\s+sys\s+ucs", body):
            return Result("S-12", GOOD, f"iCall 스크립트로 UCS 자동 백업 설정", [_short(name.split()[-1])])
    return Result("S-12", MANUAL, "장비 내 자동 UCS 백업 설정 없음 — BIG-IQ 등 외부 백업 체계·주기 증적 확인",
                  [], "iCall(periodic handler + 'tmsh save sys ucs') 또는 BIG-IQ 백업 스케줄 구성")


def s13(cfg, o):
    remote = _remote_syslog(cfg)
    if remote:
        return Result("S-13", GOOD, "원격 로그 서버 사용", remote)
    return Result("S-13", VULN, "원격 Syslog 미설정", [],
                  "tmsh modify sys syslog remote-servers add { syslog1 { host <IP> remote-port 514 } }")


def s14(cfg, o):
    ntp = cfg.obj("sys", "ntp") or EMPTY
    servers = ntp.block("servers").flat() if ntp.block("servers") else []
    tz = ntp.getstr("timezone", "기본값")
    ev = [f"sys ntp servers {{ {' '.join(servers)} }}, timezone {tz}"]
    if servers:
        return Result("S-14", GOOD, "NTP 서버 동기화 설정", ev)
    return Result("S-14", VULN, "NTP 서버 미설정", ev,
                  "tmsh modify sys ntp servers replace-all-with { <내부 NTP> } timezone Asia/Seoul")


# ---------------------------------------------------------------- 기능관리
def _virtuals(cfg):
    return {_short(n): v for n, v in cfg.objects("ltm", "virtual") if n}


def s15(cfg, o):
    vs = _virtuals(cfg)
    pools = {_short(n): p for n, p in cfg.objects("ltm", "pool") if n}
    if not vs and not pools:
        return Result("S-15", MANUAL, "ltm virtual/pool 정보 없음 — bigip.conf 포함 필요")
    disabled = [n for n, v in vs.items() if v.has("disabled")]
    empty_pool = [n for n, p in pools.items() if not p.block("members") or not p.block("members").stmts]
    orphan = [n for n, v in vs.items() if not v.has("pool") and not v.block("rules")
              and not v.has("ip-forward") and not v.has("l2-forward") and not v.has("internal")]
    ev = [f"Virtual Server {len(vs)}개, Pool {len(pools)}개"]
    if disabled:
        ev.append("비활성 VS: " + ", ".join(disabled))
    if empty_pool:
        ev.append("멤버 없는 Pool: " + ", ".join(empty_pool))
    if orphan:
        ev.append("Pool·iRule 미연결 VS: " + ", ".join(orphan))
    if disabled or empty_pool or orphan:
        return Result("S-15", VULN,
                      f"미사용 의심 객체 — 비활성 VS {len(disabled)}, 빈 Pool {len(empty_pool)}, 미연결 VS {len(orphan)}",
                      ev, "사용 여부(트래픽 통계 tmsh show ltm virtual) 확인 후 미사용 객체 삭제")
    return Result("S-15", GOOD, "미사용 Virtual Server·Pool 없음", ev)


def _dest_port(v):
    d = v.getstr("destination", "")
    m = re.search(r"[:.](\w+)$", d)
    return d, (m.group(1) if m else "")


def s16(cfg, o):
    nats = [(_short(n), node) for n, node in cfg.objects("ltm", "nat") if n]
    allports = []
    for n, v in _virtuals(cfg).items():
        d, port = _dest_port(v)
        if port in ("0", "any") and not v.has("ip-forward") and not v.has("l2-forward"):
            allports.append(f"{n} ({d})")
    ev = [f"ltm nat {n}: {node.getstr('originating-address', '?')} ↔ {node.getstr('translation-address', '?')}"
          for n, node in nats]
    ev += [f"전체 포트 VS: {x}" for x in allports]
    if nats or allports:
        return Result("S-16", VULN, f"전체 포트를 노출하는 1:1 NAT {len(nats)}건, 전체 포트 수신 VS {len(allports)}건",
                      ev, "1:1 NAT 대신 서비스 포트 단위 Virtual Server로 공개, VS destination 포트 명시")
    return Result("S-16", GOOD, "1:1 NAT 및 전체 포트 공개 Virtual Server 없음", ev or ["해당 객체 없음"])


def s17(cfg, o):
    vlans = [_short(n) for n, _ in cfg.objects("net", "vlan") if n]
    dmz = [v for v in vlans if "dmz" in v.lower()]
    ev = [f"VLAN: {', '.join(vlans) or '정보 없음'}"]
    if not dmz:
        return Result("S-17", NA, "DMZ VLAN 없음 — L4/L7 장비는 통상 방화벽 DMZ 정책으로 판단", ev)
    return Result("S-17", MANUAL, f"DMZ VLAN({', '.join(dmz)}) 존재 — 상단 방화벽 DMZ→내부 정책과 함께 확인", ev)


def s18(cfg, o):
    selfs = [(_short(n), s) for n, s in cfg.objects("net", "self") if n]
    if not selfs:
        return Result("S-18", MANUAL, "Self IP 정보 없음 — bigip_base.conf 포함 필요")
    bad, ev = [], []
    for n, s in selfs:
        allow = s.getstr("allow-service")
        if allow is None and s.block("allow-service") is not None:
            allow = " ".join(s.block("allow-service").flat())
        allow = allow or "none"
        vlan = _short(s.getstr("vlan", ""))
        ev.append(f"self {n} ({s.getstr('address', '?')}, vlan {vlan}): allow-service {allow}")
        if allow == "all":
            bad.append(f"{n}: all")
        elif allow == "default" and EXT_VLAN.search(vlan or ""):
            bad.append(f"{n}: default(외부 VLAN)")
    if bad:
        return Result("S-18", VULN, "Self IP Port Lockdown 미흡 — " + "; ".join(bad), ev,
                      "외부 VLAN Self IP: tmsh modify net self <이름> allow-service none\n"
                      "HA용 Self IP는 필요한 포트만 (예: allow-service replace-all-with { udp:1026 tcp:4353 })")
    return Result("S-18", GOOD, "Self IP 서비스 개방 최소화(Port Lockdown)", ev)


def s19(cfg, o):
    snmp = cfg.obj("sys", "snmp") or EMPTY
    traps = snmp.block("traps")
    ev = []
    if traps and traps.named():
        ev.append("SNMP Trap: " + ", ".join(f"{_short(n)} {t.getstr('host', '')}" for n, t in traps.named()))
    smtp = cfg.objects("sys", "smtp-server")
    if smtp:
        ev.append(f"SMTP 서버 설정 {len(smtp)}건(alertd 메일 알림 가능)")
    if ev:
        return Result("S-19", GOOD, "이상징후 경고(SNMP Trap/메일) 설정", ev)
    return Result("S-19", VULN, "SNMP Trap·메일 경고 설정 없음", [],
                  "tmsh modify sys snmp traps add { nms { host <NMS IP> community <문자열> version 2c } }\n"
                  "(사용자 정의 알림은 /config/user_alert.conf 별도 확인)")


def s20(cfg, o):
    return Result("S-20", MANUAL, "설정 파일로 판단 불가 — 사용량 검토 기록 확인",
                  ["tmsh show sys performance all-stats", "tmsh show sys cpu / memory"],
                  "CPU·메모리·연결 수 월간 점검 기록 및 임계치 경고 확인")


def _communities(cfg):
    snmp = cfg.obj("sys", "snmp") or EMPTY
    c = snmp.block("communities")
    return [(_short(n), node) for n, node in c.named()] if c else []


def s21(cfg, o):
    snmp = cfg.obj("sys", "snmp")
    if snmp is None:
        return Result("S-21", MANUAL, "sys snmp 설정 없음(기본 community public, 접근 127.0.0.0/8) — 장비에서 확인")
    allowed = snmp.block("allowed-addresses").flat() if snmp.block("allowed-addresses") else ["127.0.0.0/8(기본값)"]
    comms = _communities(cfg)
    users = snmp.block("users").named() if snmp.block("users") else []
    ev = [f"allowed-addresses {{ {' '.join(allowed)} }}",
          f"v1/v2c community {len(comms)}개, v3 user {len(users)}개"]
    problems = []
    if {a.lower() for a in allowed} & OPEN_ADDR:
        problems.append("SNMP 접근 허용 대역 전체")
    for n, u in users:
        if (u.getstr("auth-protocol", "none") == "none") or (u.getstr("privacy-protocol", "none") == "none"):
            problems.append(f"v3 user {n}: 인증/암호화 미사용")
    if problems:
        return Result("S-21", VULN, "; ".join(problems), ev,
                      "tmsh modify sys snmp allowed-addresses replace-all-with { <NMS IP> }\n"
                      "SNMPv3 auth-protocol sha / privacy-protocol aes 사용")
    note = " (v1/v2c 사용 — SNMPv3 전환 권고)" if comms else ""
    return Result("S-21", GOOD, "SNMP 접근 대역 제한" + note, ev)


def s22(cfg, o):
    comms = _communities(cfg)
    if not comms:
        return Result("S-22", NA if cfg.obj("sys", "snmp") else MANUAL, "v1/v2c Community 정보 없음")
    weak, ev = [], []
    for n, c in comms:
        name = c.getstr("community-name", "")
        shown = mask_secret(name) if o.mask else name
        why = community_weakness(name)
        ev.append(f'{n}: community-name "{shown}" (source {c.getstr("source", "default")})'
                  + (f" — {why}" if why else ""))
        if why:
            weak.append(f"{n}({why})")
    if weak:
        return Result("S-22", VULN, f"취약한 Community String: {', '.join(weak)}", ev,
                      "tmsh modify sys snmp communities modify { <이름> { community-name <10자 이상 복잡 문자열> "
                      "source <NMS IP> } }  (미사용 comm-public 삭제)")
    return Result("S-22", GOOD, "Community String 복잡성 충족", ev)


def s23(cfg, o):
    vs = _virtuals(cfg)
    if not vs:
        return Result("S-23", MANUAL, "Virtual Server 정보 없음 — bigip.conf 포함 필요")
    protected, unprotected = [], []
    for n, v in vs.items():
        tokens = " ".join(v.flat()).lower()
        if any(k in tokens for k in ("websecurity", "asm_", "/asm", "dos", "fw-enforced-policy",
                                     "bot-defense", "ip-intelligence")):
            protected.append(n)
        else:
            unprotected.append(n)
    asm = len(cfg.objects("asm", "policy"))
    dos = len(cfg.objects("security", "dos", "profile"))
    ev = [f"VS {len(vs)}개 중 ASM/DoS/AFM 적용 {len(protected)}개, ASM 정책 {asm}개, DoS 프로파일 {dos}개"]
    if unprotected:
        ev.append("미적용 VS: " + ", ".join(unprotected[:15]))
    if not protected:
        return Result("S-23", VULN, "Virtual Server에 WAF(ASM)·DoS 보호 미적용 — 상단 IPS/WAF 존재 시 해당 구간으로 판단",
                      ev, "서비스 VS에 ASM 정책 및 DoS 프로파일 적용 또는 상단 보안장비 차단 정책 증적 확보")
    if unprotected:
        return Result("S-23", MANUAL, f"보호 미적용 VS {len(unprotected)}개 — 내부용/상단 보호 여부 확인", ev)
    return Result("S-23", GOOD, "모든 VS에 유해 트래픽 차단 기능 적용", ev)


CHECKS = [s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11, s12,
          s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23]


def run(cfg: TmshConfig, o: Options):
    out = []
    for fn in CHECKS:
        try:
            out.append(fn(cfg, o))
        except Exception as e:
            out.append(Result(fn.__name__.upper().replace("S", "S-", 1), MANUAL, f"자동 판정 오류: {e}"))
    return out
