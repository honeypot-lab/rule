# 🛡️ Generic Detection: Potential Cryptominer Post-Exploitation Sequence

## 📝 Description
This Sigma rule is designed to detect common post-exploitation behaviors following a successful breach in a Linux environment. It specifically targets reconnaissance activities often performed by attackers before deploying cryptomining malware.

Instead of looking for a single specific indicator, this rule uses **temporal correlation** to identify a cluster of suspicious activities from the same session, which significantly reduces false positives while maintaining high detection coverage.

## 🔍 Detection Logic Summary
The rule monitors for the following behavioral indicators within a **5-minute window**:
- **Network Reconnaissance:** Use of `ifconfig` to map internal networks.
- **System Information Discovery:** Accessing `/proc/cpuinfo` to assess available computing power.
- **Conflict Checks:** Identifying and terminating competing miners using `ps | grep [Mm]iner`.
- **Environment Sanity Checks:** Using `echo Hi | cat -n` to verify shell responsiveness.
- **Specific Path Discovery:** Searching for unique configuration paths or identifiers.

## 📊 Captured Attack Scenario
The following alert was captured by our Cowrie honeypot, showing an attacker performing these exact reconnaissance steps:

![alt text](image-1.png)

> **Analysis:** The attacker successfully logged in and immediately executed a sequence of commands to check system resources and network configuration, followed by a check for existing miner processes.

## 🛠️ Rule Details
- **Log Source:** Linux / Cowrie Honeypot
- **Correlation Type:** Temporal
- **Threshold:** 3 or more distinct selection criteria met within 5 minutes.
- **Level:** High
- **MITRE ATT&CK Mapping:**
    - T1016: System Network Configuration Discovery
    - T1082: System Information Discovery
    - T1057: Process Discovery

---
*Authored by @wa__ri2*