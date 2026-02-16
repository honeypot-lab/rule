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
| **Cryptominer Reconnaissance** | `Medium` | T1082, T1057 | [🔗 보러가기](./analysis/potential-cryptominer-recon/README.md) |

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
