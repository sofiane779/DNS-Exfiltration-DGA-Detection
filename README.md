# DNS Exfiltration & DGA Detection (Splunk)

## Context
This project focuses on detecting advanced network threats that bypass traditional firewalls by using the DNS protocol. Using the **Splunk BOTS v3 dataset**, I developed a detection engine to identify **Domain Generation Algorithms (DGA)** and **DNS Tunneling/Exfiltration** attempts.

## Why this project?

Traditional security perimeters often overlook the DNS protocol, focusing primarily on HTTP/S. Attackers exploit this "silent protocol" to establish Command & Control (C2) communications via DGA or to exfiltrate data through DNS tunneling, bypassing standard Data Loss Prevention (DLP) systems.

## Project Goals

To address these stealthy threats, this project implements a specialized detection engine in Splunk designed to:

* Identify Structural Anomalies: Detect unusually long DNS queries that often hide encoded data.

* Analyze Entropy: Use a "Complexity Score" to distinguish between human-readable domains and machine-generated (DGA) strings.

* Automate Response: Transform raw network logs into actionable security alerts.

## Master Detection Rule (SPL)

This rule combines structural analysis and complexity scoring to flag high-risk domains:

```spl
source="botsv3_data_set.tgz:*" 
| where isnotnull(query)
| eval query_len = len(query)
| rex field=query "(?<numbers>\d)" max_match=100
| eval num_count = mvcount(numbers), complexity_score = if(isnotnull(num_count), num_count / query_len, 0)
| stats count as freq, avg(query_len) as avg_len, max(complexity_score) as max_complexity by query, src
| where avg_len > 25 OR max_complexity > 0.3
| sort - avg_len
```

## Technical Analysis & Findings

1. Structural Triage (Length Analysis)
By analyzing the distribution of query lengths, I established a baseline where domains exceeding 25 characters are flagged for further inspection. This successfully isolated several static provider domains and potential exfiltration strings.

2. Complexity Scoring (Entropy Simulation)
Since DGA domains often use high-entropy strings (mix of numbers and random letters), I implemented a complexity_score.

   * Logic: num_count / query_len.

   * Threshold: Any domain where numbers represent more than 30% of the string is flagged as a potential algorithmic generation.

## Detailed Documentation

* Logic Breakdown: Deep dive into the eval functions and the regex used to calculate entropy.

* Evidence Guide: Screenshots of the Master query results and the statistical distribution.

## Repository Structure


```text
├── DETECTION_LOGIC.md       
├── LICENSE                   
├── README.md                 
└── EVIDENCE/                 
    ├── MASTER.png
    ├── DNS_STATISTICAL_TRIAGE.png
    └── DNS_COMPLEXITY_SCORE_RULE.png
```

## How to Reproduce

To validate this detection logic, follow these steps:

1. **Dataset:** Access the **Splunk BOTS v3** dataset.
2. **Time Range:** Set the picker to **"All time"** (historical data).
3. **Execution:** Copy the SPL query found in [DETECTION_LOGIC.md](./DETECTION_LOGIC.md).
4. **Verification:** Compare your results with the provided [Master Evidence](./EVIDENCE/MASTER.png).



