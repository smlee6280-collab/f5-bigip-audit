# f5-bigip-audit

**F5 BIG-IP(L4/L7 스위치) 설정 파일 기반 보안장비 취약점 점검 도구**

주요정보통신기반시설 기술적 취약점 분석·평가 기준의 **보안장비 항목(S-01 ~ S-23)** 을
BIG-IP 설정 파일만으로 자동 판정하고, 진단 보고서(HTML)·조치계획·CSV를 생성합니다.

장비에 접속하지 않고 **설정 파일만** 읽기 때문에 운영 영향이 없고,
여러 대를 한 번에 점검해 장비별 결과를 한 표로 비교할 수 있습니다.

> 만든 이유: 금융권 F5 BIG-IP LTM/ASM 등 L4/L7 장비 약 40대를 점검하면서
> 장비마다 반복되는 설정 확인을 자동화하고, 진단자가 판단과 권고에 집중할 수 있게 하려고 만들었습니다.
>
> 제작 방식: 점검 항목 체계와 항목별 양호/취약 판정 기준은 실무 점검·평가 대응 경험을 바탕으로 직접 설계했고,
> 코드 구현은 AI 도구(Claude)를 활용했습니다.

---

## 주요 기능

| 기능 | 내용 |
|---|---|
| 지원 장비 | F5 BIG-IP TMOS 13 ~ 17 (LTM, ASM, AFM) |
| 점검 항목 | 계정관리 S-01~05 · 접근관리 S-06~08 · 패치관리 S-09 · 로그관리 S-10~14 · 기능관리 S-15~23 |
| 판정 | 양호 / 취약 / 수동확인 / 해당없음 — 근거(현재 설정)와 tmsh 조치 명령어를 함께 제시 |
| 기본값 처리 | 설정 파일에 없는 값은 TMOS 기본값으로 판단 (예: `max-login-failures` 0 = 잠금 없음, `sshd allow` 미설정 = ALL) |
| 출력 | 장비별 보고서, 전체 결과 매트릭스(`summary.html`), `results.csv`(Excel), `results.json` |
| 보고서 구성 | 결과 요약·준수율 → 취약 항목 조치계획(중요도순, 담당/완료예정 칸) → 수동확인 항목 → 항목별 상세 |
| 민감정보 | SNMP Community String은 기본 마스킹(`pu****`) — 증적 공유 시 노출 방지 |
| 의존성 | 없음 (Python 3.10+ 표준 라이브러리만 사용, 폐쇄망 반입 용이) |

## 사용법

```bash
# 샘플 2대 점검
python -m secaudit samples -o out

# 분할된 설정 파일을 한 장비로 합쳐 점검
python -m secaudit bigip_base.conf bigip.conf bigip_user.conf --merge --name LTM-01 -o out

# 여러 장비 폴더 일괄 점검 + 기준 버전 지정(미만이면 S-09 취약)
python -m secaudit configs/ -o out --min-version 17.1.2

# 기준값 조정
python -m secaudit configs/ --session-timeout 300 --log-retention-days 365
```

실행 결과(콘솔):

```
장비                    TMOS          양호  취약  수동  해당없음  준수율
ltm01.example.local   15.1.8         1  18   3     1  5.3%
  └ 취약: S-01, S-02, S-03, S-04, S-05, S-06, S-07, S-08, S-11, S-13, S-14, S-15, S-16, S-18, S-19, S-21, S-22, S-23
ltm02.example.local   17.1.2        19   0   3     1  100.0%
```

### 설정 파일 확보 방법
| 방법 | 내용 |
|---|---|
| 설정 파일 | `/config/bigip_base.conf`(네트워크·시스템), `/config/bigip.conf`(LTM 객체), `/config/bigip_user.conf`(계정) |
| tmsh 출력 | `tmsh -q list` 또는 `tmsh show running-config` 결과를 파일로 저장 |

계정 항목(S-01~05)은 `bigip_user.conf`, Self IP·관리접속 항목은 `bigip_base.conf`, VS·Pool 항목은 `bigip.conf`에 있으므로
세 파일을 `--merge`로 함께 넣는 것을 권장합니다.

## 점검 항목과 판정 로직

| 코드 | 항목 | 확인 설정 | 취약 판정 예 |
|---|---|---|---|
| S-01 | 기본 관리자 계정 변경 | `auth user admin`, `sys db systemauth.primaryadminuser`, `systemauth.disablerootlogin` | admin 계정 사용, root SSH 허용 |
| S-02 | 비밀번호 관리 정책 | `auth password-policy` | `policy-enforcement disabled`, 8자 미만 |
| S-03 | 계정별 권한 설정 | 계정별 `partition-access` role | 모든 계정이 admin |
| S-04 | 1인 1계정·불필요 계정 | 계정명 | test·temp·guest 등 공용/임시 계정 |
| S-05 | 계정 잠금 임계값 | `max-login-failures` | 0(무제한) 또는 5회 초과 |
| S-06 | 원격 관리 접근 통제 | `sys sshd allow`, `sys httpd allow` | 미설정(ALL) 또는 0.0.0.0/0 |
| S-07 | 보안 접속 | `sys httpd ssl-protocol` | SSLv3·TLS1.0·TLS1.1 허용 |
| S-08 | 세션 종료 시간 | `sshd inactivity-timeout`, `httpd auth-pam-idle-timeout` | 0(무제한) 또는 기준 초과 |
| S-09 | 보안 패치 | `#TMSH-VERSION` | 지원 종료 브랜치, `--min-version` 미만 |
| S-10 | 로그 설정 | `sys db config.auditing` | 감사 로그 비활성 |
| S-11 | 로그 보관 | 원격 Syslog 여부 | 로컬만 보관(logrotate 순환 삭제) |
| S-12 | 정책 백업 | iCall 스크립트의 `save sys ucs` | 없으면 수동확인(외부 백업 증적) |
| S-13 | 원격 로그 서버 | `sys syslog remote-servers`, HSL | 미설정 |
| S-14 | NTP 동기화 | `sys ntp servers` | 미설정 |
| S-15 | 미사용 정책 정리 | `ltm virtual` disabled, 멤버 없는 `ltm pool`, Pool·iRule 미연결 VS | 미사용 객체 존재 |
| S-16 | NAT 설정 | `ltm nat`, VS destination 포트 | 1:1 NAT(전체 포트), `:0` 전체 포트 VS |
| S-17 | DMZ 설정 | DMZ VLAN | DMZ VLAN 있으면 수동확인(상단 방화벽 정책과 함께) |
| S-18 | 최소 서비스 | Self IP `allow-service` (Port Lockdown) | `all`, 외부 VLAN에 `default` |
| S-19 | 이상징후 경고 | `sys snmp traps`, `sys smtp-server` | 경고 전달 설정 없음 |
| S-20 | 장비 사용량 검토 | — | 수동확인(점검 명령어 제시) |
| S-21 | SNMP 서비스 | `sys snmp allowed-addresses`, v3 user | 전체 허용, v3 인증·암호화 미사용 |
| S-22 | Community String | `community-name` | public/private, 10자 미만, 단일 문자종류 |
| S-23 | 유해 트래픽 차단 | VS의 ASM(websecurity)·DoS·AFM 적용 | 모든 VS에 미적용 |

## 설계 원칙

- **자동 판정의 한계를 명시**: 설정만으로 판단할 수 없는 항목(S-04 1인 1계정, S-12 외부 백업, S-20 사용량)은
  억지로 양호/취약을 매기지 않고 `수동확인` 으로 분류해 인터뷰·증적 확인 방법을 함께 제시합니다.
- **기본값을 아는 판정**: tmsh 설정은 기본값을 출력하지 않는 경우가 많아, 값이 없을 때 TMOS 기본값으로 판단하고
  근거에 `(기본값)`을 표시합니다.
- **근거 중심**: 모든 판정에 실제 설정 내용을 근거로 남겨 진단자가 결과를 바로 검증하고 보고서 증적으로 쓸 수 있습니다.
- **이행 가능한 권고**: 조치방안은 tmsh 명령어로 제시해 운영자가 그대로 적용할 수 있게 했습니다.
- **iRule 안전 처리**: iRule·iCall의 Tcl 본문은 파싱하지 않고 원문으로 보관해, 중괄호가 섞인 스크립트가 설정 구조 해석을 깨지 않게 했습니다.

## 구조

```
secaudit/
├─ parse_tmsh.py   # tmsh 중괄호 계층 파서 (iRule·iCall 원문 보관)
├─ checks_f5.py    # S-01~S-23 판정 로직
├─ model.py        # 항목 정의·판단 기준·결과 모델
├─ report.py       # HTML/CSV/JSON 보고서
└─ __main__.py     # CLI
samples/           # 취약/양호 샘플 설정 (가상 IP, 가상 해시)
tests/             # 회귀 테스트: python -m unittest discover -s tests -t .
```

## 유의사항

- 항목 명칭·판단 기준은 평가 기준의 보안장비 항목 체계를 정리한 것으로, 실제 평가 시 해당 연도 상세가이드 원문과 대조해 기준값을 조정합니다(`--session-timeout`, `--log-retention-days` 등).
- 자동 판정은 진단자의 1차 확인용이며, 최종 판정은 장비 상태·운영 환경 확인 후 진단자가 확정합니다.
- 샘플 설정의 IP·계정·해시는 모두 가상의 값입니다. 실제 고객사 설정 파일은 저장소에 올리지 마세요.

## 로드맵

- [ ] 이전 점검 결과와 비교(이행 점검: 조치 완료 / 미조치 자동 표시)
- [ ] ASM 정책 세부 점검(Blocking/Transparent 모드, 시그니처 스테이징)
- [ ] 엑셀 진단 결과표 양식 출력
