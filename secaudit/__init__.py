"""f5-bigip-audit: F5 BIG-IP 설정 파일 기반 보안장비 취약점 점검 도구."""
from pathlib import Path

from . import checks_f5, parse_tmsh
from .model import DeviceReport, Options

__version__ = "1.0.0"

F5_MARKERS = ("#TMSH-VERSION", "ltm virtual ", "sys global-settings", "auth user ", "net self ", "sys sshd")


def is_f5(text: str) -> bool:
    return any(k in text for k in F5_MARKERS)


def audit_text(text: str, name: str, source: str, opts: Options) -> DeviceReport:
    if not is_f5(text):
        raise ValueError(f"{source}: F5 BIG-IP(tmsh) 설정 형식이 아닙니다")
    cfg = parse_tmsh.parse(text)
    gs = cfg.obj("sys", "global-settings")
    host = gs.getstr("hostname") if gs else None
    return DeviceReport(name or host or Path(source).stem, "F5", "BIG-IP", cfg.version or "",
                        source, checks_f5.run(cfg, opts))
