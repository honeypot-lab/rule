# 🛡️ Sigma Rules for Cowrie Honeypot Analysis

이 리포지토리는 Cowrie 허니팟에 수집된 실제 공격 로그를 분석하고, 이를 탐지하기 위한 **Sigma Rules**를 체계적으로 관리하는 프로젝트입니다. 모든 룰은 GitHub Actions를 통해 표준 시그마 스키마 검증을 거칩니다.

## 🚀 프로젝트 핵심 가치
* **Real-world Analysis:** 허니팟에 수집된 실제 인텔리전스를 바탕으로 위협을 정의합니다.
* **Hierarchical Detection:** 단일 행위(Standard)와 행위 간의 흐름(Correlation)을 분리하여 탐지 신뢰도를 극대화합니다.
* **DevSecOps:** CI/CD 워크플로우를 통한 자동화된 룰 유효성 검증을 지원합니다.

---

## 📂 리포지토리 구조 (Repository Structure)

```text
.
├── .github/workflows       # 룰 자동 검증 (Sigma-Linter)
├── analysis                # 공격별 상세 분석 보고서 및 로그 샘플
│   ├── iranbot-malware     # Iranbot One-liner 배포 분석
│   └── potential-miner     # 채굴기 유포 전 정찰 행위 분석
├── sigma_rules             # 실제 운영 환경용 Sigma 룰 모음
│   ├── standard            # 단일 이벤트 탐지 룰 (Atomic)
│   └── correlation         # 상관관계 분석 룰 (Sequence)
└── README.md               # 프로젝트 메인 가이드
```

---

## 🛡️ 주요 분석 사례 (Key Analysis)
| 분석 사례 (Attack Cases) | 위협 수준 | 관련 TTPs | 상세 보고서 |
|:--- |:---:|:---|:---:|
| **Iranbot Malware Deployment** | `Critical` | T1059.004, T1105 | [🔗 보러가기](./analysis/iranbot-malware/README.md) |
| **High-Risk Multi-Path Delivery** | `Critical` | T1070.004, T1105 | [🔗 보러가기](./analysis/multi-path-delivery-cleanup/README.md) |
| **Multi-Tool Persistent Delivery** | `Critical` | T1105, T1059 | [🔗 보러가기](./analysis/multi-tool-persistent-delivery/README.md) |
| **Cisco-Targeted Botnet** | `High` | T1059.004, T1105, T1222 | [🔗 보러가기](./analysis/cisco-targeted-botnet/README.md) |
| **Cryptominer Reconnaissance** | `Medium` | T1082, T1057 | [🔗 보러가기](./analysis/potential-cryptominer-recon/README.md) |

---

## 🤖 실시간 침해지표 알림 시스템 (Discord Integration)

단순한 로그 누적을 넘어 탐지의 **실시간성(Real-time Visibility)**을 확보하기 위해, 직접 개발한 `Cowrie-Discord Alert Bot`을 연동하여 운영 중입니다.

### 🛠️ 주요 기능 및 아키텍처
* **실시간 로그 파싱:** `cowrie.json`에 기록되는 로우 데이터(Raw Data)를 Python 스크립트가 실시간으로 테일링(Tailing)하며 파싱합니다.
* **지능형 노이즈 필터링:** 단순 스캔이나 의미 없는 중복 접속 시도 등 분석 가치가 낮은 데이터를 필터링 로직으로 제거하여 분석 피로도를 낮췄습니다.
* **고위험 행위 우선순위 지정:** `wget`, `chmod 777`, `rm -rf`, `tftp` 등 실제 침해 사고와 직결되는 핵심 키워드 탐지 시 즉시 알림을 생성합니다.
* **위협 인텔리전스(CTI) 연동:** **AbuseIPDB API**를 연동하여 공격 IP의 위험 점수(Abuse Score)와 리포트 건수를 알림 메시지에 포함함으로써, 공격의 심각도를 즉각 판단할 수 있게 구현했습니다.



### 💡 기대 효과
* **기민한 분석 환경:** 공격 발생과 동시에 TTP(전술·기법·절차)를 파악하고, 신규 Sigma 룰을 즉시 작성 및 테스트할 수 있는 파이프라인을 구축했습니다.
* **상시 모니터링 체계:** 별도의 관리 콘솔 접속 없이도 Discord 앱을 통해 모바일 및 PC 환경에서 최신 봇넷 페이로드와 공격 트렌드를 실시간으로 모니터링합니다.

---

## 🚀 프로젝트 핵심 가치
* **실전 기반 분석(Real-world Analysis):** 허니팟에 수집된 실제 인텔리전스를 바탕으로 위협을 정의합니다.
* **계층적 탐지(Hierarchical Detection):** 단일 행위(Standard)와 행위 간의 흐름(Correlation)을 분리하여 탐지 신뢰도를 극대화합니다.
* **실시간 대응 체계(Real-time Response):** 자체 개발한 Discord 봇을 통해 고위험 공격에 대한 상시 모니터링 시스템을 가동합니다.
* **DevSecOps 기반 검증:** CI/CD 워크플로우를 통한 자동화된 룰 유효성 검증을 지원합니다.

---

## ⚙️ 룰 검증 및 배포 (Validation)

본 리포지토리의 모든 Sigma 룰은 다음 스키마를 준수하며 GitHub Actions를 통해 자동화된 검증을 수행합니다.

* **Standard Rules:** [Sigma Detection Schema](https://github.com/SigmaHQ/sigma-specification)
* **Correlation Rules:** [Sigma Correlation Schema v2.1.0](https://github.com/SigmaHQ/sigma-specification)

---

## 🛠️ 사용 방법 (How to Use)

1.  **분석 참조:** `analysis/` 폴더 내의 `README.md`와 `sample.json`을 통해 실제 공격 패턴과 탐지 로직의 근거를 이해합니다.
2.  **룰 적용:** `sigma_rules/` 내의 `.yml` 파일들을 [sigmac](https://github.com/SigmaHQ/sigma) 또는 [sigma-cli](https://github.com/SigmaHQ/sigma-cli)를 사용하여 타겟 환경(Elasticsearch, Splunk, Sentinel 등)으로 변환하여 적용합니다.

---
**Maintained by:** [@BISHOP1027](https://github.com/BISHOP1027)
