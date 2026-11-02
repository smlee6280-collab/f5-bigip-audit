"""점검 항목 정의와 결과 모델.

항목 체계는 주요정보통신기반시설 기술적 취약점 분석·평가 기준의 보안장비 항목(S-01~S-23)을
계정관리 / 접근관리 / 패치관리 / 로그관리 / 기능관리 5개 영역으로 정리한 것이다.
항목 명칭과 판단 기준은 실제 평가 시 해당 연도 상세가이드 원문과 대조해 사용한다.
"""
from dataclasses import dataclass, field, asdict

GOOD = "양호"
VULN = "취약"
MANUAL = "수동확인"
NA = "해당없음"
STATUS_ORDER = [VULN, MANUAL, GOOD, NA]


@dataclass(frozen=True)
class Item:
    code: str
    category: str
    title: str
    importance: str  # 상/중/하
    criteria: str    # 판단 기준(양호 조건)


ITEMS = [
    Item("S-01", "계정관리", "기본 관리자 계정 변경", "상",
         "제조사 기본 관리자 계정(admin, root 등)을 사용하지 않거나 비활성화한 경우 양호"),
    Item("S-02", "계정관리", "비밀번호 관리 정책", "상",
         "비밀번호 복잡도 정책이 적용되어 최소 8자 이상, 2종류 이상 문자 조합을 강제하는 경우 양호"),
    Item("S-03", "계정관리", "계정별 권한 설정", "중",
         "관리자 계정별로 업무에 맞는 권한이 분리되어 있는 경우 양호"),
    Item("S-04", "계정관리", "계정 관리(1인 1계정, 불필요 계정)", "중",
         "공용·테스트·임시 계정이 없고 계정이 사용자별로 부여된 경우 양호"),
    Item("S-05", "계정관리", "계정 잠금 임계값 설정", "중",
         "로그인 실패 5회 이하에서 계정 잠금이 동작하는 경우 양호"),
    Item("S-06", "접근관리", "원격 관리 접근 통제", "상",
         "관리 접속(GUI/SSH)이 허용된 관리자 IP 대역으로만 제한된 경우 양호"),
    Item("S-07", "접근관리", "보안 접속(암호화 프로토콜)", "상",
         "Telnet·HTTP 등 평문 관리 프로토콜과 취약한 TLS 버전을 사용하지 않는 경우 양호"),
    Item("S-08", "접근관리", "세션 종료 시간 설정", "중",
         "관리 세션 유휴 시 기준 시간(기본 10분) 이내 자동 종료되는 경우 양호"),
    Item("S-09", "패치관리", "보안 패치 및 벤더 권고사항 적용", "상",
         "벤더 지원 중인 버전이며 공개된 보안 취약점(PSIRT)에 대한 패치가 적용된 경우 양호"),
    Item("S-10", "로그관리", "로그 설정", "상",
         "관리자 이벤트·트래픽 로그가 기록되도록 설정된 경우 양호"),
    Item("S-11", "로그관리", "로그 보관", "중",
         "로그를 원격 서버 또는 로컬에 기준 기간 이상 보관하는 경우 양호"),
    Item("S-12", "로그관리", "정책 백업 설정", "중",
         "설정·정책을 주기적으로 백업하는 체계가 있는 경우 양호"),
    Item("S-13", "로그관리", "원격 로그 서버 사용", "중",
         "Syslog·로그 분석 서버로 로그를 전송하는 경우 양호"),
    Item("S-14", "로그관리", "NTP 시각 동기화", "중",
         "NTP 서버와 시각 동기화가 설정된 경우 양호"),
    Item("S-15", "기능관리", "미사용·과도 허용 정책 정리", "상",
         "비활성(미사용) 정책과 출발지·목적지·서비스가 모두 Any인 허용 정책이 없는 경우 양호"),
    Item("S-16", "기능관리", "NAT 설정", "중",
         "목적지 NAT가 필요한 서비스 포트로만 한정된 경우 양호"),
    Item("S-17", "기능관리", "DMZ 설정", "중",
         "DMZ에서 내부망으로의 접근이 필요한 대상·서비스로만 제한된 경우 양호"),
    Item("S-18", "기능관리", "최소한의 서비스만 허용", "상",
         "외부(WAN) 인터페이스에서 관리·불필요 서비스가 열려 있지 않은 경우 양호"),
    Item("S-19", "기능관리", "이상징후 탐지 경고 설정", "중",
         "장애·보안 이벤트 발생 시 메일·SNMP Trap 등으로 경고가 전달되는 경우 양호"),
    Item("S-20", "기능관리", "장비 사용량 검토", "하",
         "CPU·메모리·세션 사용량을 주기적으로 검토하는 경우 양호"),
    Item("S-21", "기능관리", "SNMP 서비스 설정", "중",
         "SNMP 미사용 시 비활성화, 사용 시 접근 가능 호스트가 제한되고 SNMPv3 권고"),
    Item("S-22", "기능관리", "SNMP Community String 복잡성", "중",
         "Community String이 기본값(public/private)이 아니고 10자 이상 복잡하게 설정된 경우 양호"),
    Item("S-23", "기능관리", "유해 트래픽 차단 정책", "상",
         "IPS·DoS·WAF 등 유해 트래픽 차단 기능이 서비스 정책에 적용된 경우 양호"),
]
ITEM_MAP = {i.code: i for i in ITEMS}


@dataclass
class Result:
    code: str
    status: str
    detail: str
    evidence: list = field(default_factory=list)
    remedy: str = ""

    @property
    def item(self) -> Item:
        return ITEM_MAP[self.code]

    def to_dict(self):
        d = asdict(self)
        d.update(category=self.item.category, title=self.item.title,
                 importance=self.item.importance, criteria=self.item.criteria)
        return d


@dataclass
class DeviceReport:
    name: str
    vendor: str
    model: str
    version: str
    source: str
    results: list

    def counts(self):
        c = {s: 0 for s in STATUS_ORDER}
        for r in self.results:
            c[r.status] += 1
        return c

    def score(self):
        c = self.counts()
        judged = c[GOOD] + c[VULN]
        return round(c[GOOD] * 100 / judged, 1) if judged else None


@dataclass
class Options:
    session_timeout: int = 600       # 초
    log_retention_days: int = 180
    min_version: str | None = None   # 예: 7.4.8 (지정 시 이 버전 미만은 취약)
    mask: bool = True


def mask_secret(s: str, show: int = 2) -> str:
    if s is None:
        return ""
    return s[:show] + "*" * max(len(s) - show, 3)


def ver_tuple(v: str):
    out = []
    for p in v.split("."):
        num = "".join(ch for ch in p if ch.isdigit())
        out.append(int(num) if num else 0)
    while len(out) < 3:
        out.append(0)
    return tuple(out[:3])


WEAK_COMMUNITIES = {"public", "private", "community", "snmp", "cisco", "f5", "bigip",
                    "admin", "default", "test", "monitor", "manager", "secret", "read", "write"}
GENERIC_ACCOUNT_PREFIXES = ("test", "guest", "temp", "tmp", "demo", "user", "share", "common")


def char_classes(s: str) -> int:
    return sum([any(c.islower() for c in s), any(c.isupper() for c in s),
                any(c.isdigit() for c in s), any(not c.isalnum() for c in s)])


def community_weakness(name: str):
    """취약 사유 문자열 또는 None."""
    if name.lower() in WEAK_COMMUNITIES:
        return "추측 가능한 기본/일반 문자열"
    if len(name) < 10:
        return f"길이 {len(name)}자(10자 미만)"
    if char_classes(name) < 2:
        return "단일 문자 종류"
    return None


def is_generic_account(name: str) -> bool:
    n = name.lower()
    return any(n.startswith(p) for p in GENERIC_ACCOUNT_PREFIXES)
