# Evidence Guide - DNS Threat Detection

This directory contains the visual proof of the detection logic implemented in Splunk using the BOTS v3 dataset.

## Files Inventory

### 1. [DNS_STATISTICAL_TRIAGE.png](./DNS_STATISTICAL_TRIAGE.png)
* **Description:** Initial query showing the calculation of domain lengths.
* **Key Evidence:** Demonstrates the ability to use `eval` and `len()` to transform raw DNS strings into measurable metrics. It shows the identification of long domains (30+ characters) which are potential candidates for exfiltration.

### 2. [DNS_COMPLEXITY_SCORE_RULE.png](./DNS_COMPLEXITY_SCORE_RULE.png)
* **Description:** Execution of the entropy-proxy logic (Complexity Score).
* **Key Evidence:** Shows the successful use of Regular Expressions (`rex`) to extract digits and calculate the ratio of numbers vs. length. This proves the logic used to flag DGA-style domains.

### 3. [MASTER.png](./MASTER.png)
* **Description:** Final consolidated detection dashboard/result.
* **Key Evidence:** This is the "Money Shot". It shows the final 10 high-fidelity events where both length and complexity thresholds were met. It includes the source IPs, timestamps, and the specific suspicious queries.

---
