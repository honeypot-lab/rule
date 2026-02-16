# 🛡️ Attack Analysis: Potential Cryptominer Post-Exploitation Recon

## 1. 개요 (Executive Summary)
본 분석은 Cowrie 허니팟에 수집된 암호화폐 채굴기(Cryptominer) 유포 전 단계의 정찰 행위를 다룹니다. 공격자는 침투 성공 후 시스템 자원 확인, 네트워크 구성 파악, 그리고 경쟁 채굴기 존재 여부를 확인하는 전형적인 **Post-Exploitation** 패턴을 보였습니다.

- **분석 일시:** 2026-02-08
- **공격자 IP:** `116.120.157.4` (대한민국, SK Broadband)
- **위협 수준:** Medium (Reconnaissance)
- **타겟 서비스:** SSH (Cowrie Honeypot)

## 2. 공격 타임라인 및 분석 (Attack Lifecycle)

제공된 `sample.json` 로그에 따르면, 공격자는 세션 연결 후 약 2초 내에 다음의 정찰 명령어를 집중적으로 수행했습니다.

| 시간 (UTC) | 명령어 (Input) | 분석 및 의도 |
|:---|:---|:---|
| 02:47:01 | `/ip cloud print` | MikroTik 장비 여부 확인 및 클라우드 설정 정찰 |
| 02:47:02 | `ifconfig` | 네트워크 인터페이스 및 내부 IP 구성 확인 |
| 02:47:02 | `cat /proc/cpuinfo` | CPU 코어 수 및 성능 확인 (채굴 효율성 계산) |
| 02:47:02 | `ps \| grep '[Mm]iner'` | 이미 실행 중인 타사 채굴 프로세스 탐색 (경쟁자 제거 목적) |
| 02:47:03 | `locate D877F783...` | 특정 악성코드 잔재 또는 설정 파일 존재 여부 확인 |
| 02:47:03 | `echo Hi \| cat -n` | 쉘의 정상 작동 여부 및 기본 명령어 실행 환경 확인 (Sanity Check) |

### 실제 탐지 화면 (Cowrie Dashboard)
![Recon Alert](./image.png)
> **비고:** AbuseIPDB 기준 해당 IP는 100/100의 위험도를 가진 상습 공격지로 확인되었습니다.

## 3. 탐지 전략 (Detection Strategy)

이 공격 패턴을 효과적으로 탐지하기 위해 두 가지 단계의 Sigma 룰을 구성하였습니다.

### A. 개별 이벤트 탐지 (Atomic Detection)
- **파일명:** [`miner_recon_events.yml`](../../sigma_rules/standard/miner_recon_events.yml)
- **설명:** `/proc/cpuinfo` 접근이나 `ps | grep miner`와 같은 개별적인 정찰 행위를 식별합니다.

### B. 상관관계 분석 (Correlation Detection)
- **파일명:** [`miner_recon_sequence.yml`](../../sigma_rules/correlation/miner_recon_sequence.yml)
- **설명:** 단일 명령어는 오탐의 소지가 있으므로, **5분 이내에 위 정찰 명령어 중 3개 이상이 동시에 발생**할 경우 고위험군으로 분류하여 알람을 생성합니다.

## 4. 대응 권고 사항
- 불필요한 시스템 정보 노출을 최소화하기 위해 `/proc` 파일 시스템에 대한 접근 권한 제어.
- `ifconfig`, `ps` 등 시스템 관리 도구에 대한 비정상적인 호출 모니터링 강화.
- 알려진 공격 IP(`116.120.157.4`)에 대한 방화벽 차단 조치.