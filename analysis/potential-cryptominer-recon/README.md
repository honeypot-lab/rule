# 🛡️ Attack Analysis: Potential Cryptominer Post-Exploitation Recon

## 1. 개요 (Executive Summary)
본 분석은 Cowrie 허니팟에 수집된 암호화폐 채굴기(Cryptominer) 유포 전 단계의 정찰 행위를 다룹니다. 공격자는 침투 성공 후 시스템 자원 확인, 네트워크 구성 파악, 그리고 경쟁 채굴기 존재 여부를 확인하는 전형적인 **Post-Exploitation** 패턴을 보였습니다.

- **분석 일시:** 2026-02-08
- **공격자 IP:** `116.120.157.4` (대한민국, SK Broadband)
- **위협 수준:** Medium (Reconnaissance)
- **타겟 서비스:** SSH (Cowrie Honeypot)

## 2. TTP 분석 (MITRE ATT&CK Matrix)
공격자의 행위를 MITRE ATT&CK 프레임워크에 기반하여 분류한 결과입니다.

| 전술 (Tactics) | 기법 ID | 기법명 (Technique) | 상세 행위 |
|:---|:---|:---|:---|
| **Discovery** | T1082 | System Information Discovery | `/proc/cpuinfo`를 통한 하드웨어 사양 확인 |
| **Discovery** | T1016 | System Network Configuration Discovery | `ifconfig`를 통한 네트워크 구성 확인 |
| **Discovery** | T1057 | Process Discovery | `ps | grep miner`로 경쟁 채굴기 탐색 |
| **Discovery** | T1083 | File and Directory Discovery | `locate`를 이용한 특정 설정 파일 탐색 |

## 3. IoC (Indicators of Compromise)
본 정찰 행위와 관련된 주요 지표입니다.

| 유형 | 값 (Value) | 비고 |
|:---|:---|:---|
| **IPv4** | `116.120.157.4` | 상습적인 SSH Brute-force 공격지 |
| **Command** | `/ip cloud print` | MikroTik 장비 정찰 시그니처 |
| **Command** | `ps | grep '[Mm]iner'` | 경쟁 프로세스 탐색 패턴 |

## 4. 공격 타임라인 및 분석 (Attack Lifecycle)

제공된 [`sample.json`](./sample.json) 로그에 따르면, 공격자는 세션 연결 후 약 2초 내에 다음의 정찰 명령어를 집중적으로 수행했습니다.

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

## 5. 탐지 전략 (Detection Strategy)

본 사례는 단일 명령어로는 오탐 가능성이 높은 정찰 행위들을 논리적으로 결합하여 탐지하는 **계층형 탐지(Layered Detection)** 모델을 적용합니다.

### A. 표준 이벤트 탐지 (Standard/Atomic Detection)
공격자가 침투 직후 수행하는 시스템 정보 수집 행위들을 개별적으로 식별합니다.

* **자원 정찰 탐지 ([`lnx-recon-cpu-info.yml`](../../sigma_rules/standard/lnx-recon-cpu-info.yml))**: `/proc/cpuinfo` 조회를 통한 CPU 코어 및 성능 확인 행위를 포착합니다.
* **네트워크 정찰 탐지 ([`lnx-recon-network-discovery.yml`](../../sigma_rules/standard/lnx-recon-network-discovery.yml))**: `ifconfig` 등을 이용한 인터페이스 및 내부망 구성 파악 시도를 식별합니다.
* **경쟁 마이너 탐색 탐지 ([`lnx-recon-miner-check.yml`](../../sigma_rules/standard/lnx-recon-miner-check.yml))**: `ps`와 `grep`을 조합하여 시스템 내 타사 채굴기 존재 여부를 확인하는 행위를 탐지합니다.
* **환경 건전성 확인 탐지 ([`lnx-recon-sanity-check.yml`](../../sigma_rules/standard/lnx-recon-sanity-check.yml))**: `echo Hi`, `locate` 등을 사용한 쉘 기능 테스트 및 MikroTik 장비 여부 확인 시도를 포착합니다.

---

### B. 상관관계 분석 (Correlation/Behavioral Detection)
짧은 시간 내에 발생하는 다수의 정찰 행위를 묶어 공격자의 최종 의도(채굴기 배포 준비)를 확정적으로 식별합니다.

* **파일명**: [`corr-lnx-miner-recon-chain.yml`](../../sigma_rules/correlation/corr-lnx-miner-recon-chain.yml)
* **탐지 로직**: 
    1. 동일 세션 내에서 위 4가지 **표준 정찰 이벤트**가 독립적으로 발생함
    2. 5분(Timespan) 이내에 서로 다른 **정찰 행위 중 3개 이상**이 집중될 경우 탐지
* **효과**: 관리자의 정상적인 시스템 점검(단발성 `ps`나 `ifconfig` 사용)과 공격자의 자동화된 정찰 시퀀스를 명확히 구분하여 알람 피로도를 획기적으로 낮춥니다.

---
**Authored by**: [@BISHOP1027](https://github.com/BISHOP1027)