# DETECTION_LOGIC.md: Technical Deep Dive
This document provides a detailed breakdown of the mathematical and logical functions used to detect DNS anomalies within the BOTS v3 dataset.

## 1. Structural Triage (Length Analysis)

The first step in our detection engine is to transform raw string data into a numerical metric to identify potential data exfiltration or tunneling.

* SPL Logic: | eval query_len = len(query)

* Objective: Isolate abnormally long queries. In the BOTS v3 environment, we observed that domains exceeding 25 characters often represent encoded data or complex C2 structures rather than human-readable navigation.

Click to enlarge (Source: DNS_STATISTICAL_TRIAGE.png)

## 2. Complexity Scoring (Entropy Proxy)

To detect Domain Generation Algorithms (DGA), we measure the density of numerical characters within the domain name. A high ratio is a strong indicator of machine-generated strings.

* Digit Extraction: | rex field=query "(?<numbers>\d)" max_match=100

* Ratio Calculation: | eval complexity_score = num_count / query_len

* Threshold: Set at > 0.3. If 30% of a domain string consists of digits, it is flagged as "High Complexity" and highly suspicious.

Click to enlarge (Source: DNS_COMPLEXITY_RULE.png)

## 3. Master Consolidation & Final Results

The final "Master" rule aggregates these metrics to present only high-fidelity alerts, eliminating background noise from legitimate short-lived sessions.

* Command: | stats count as freq, avg(query_len) as avg_len, max(complexity_score) as max_complexity by query, src

* Outcome: We obtain a precise list of source IPs (src) interacting with suspicious domains. This allows an analyst to prioritize investigations based on the highest average length and complexity scores.

Click to enlarge (Source: MASTER.png)
