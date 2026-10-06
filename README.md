# Technique 2: Network Port Scan Detection (Nmap)

## Overview

A full TCP SYN scan (`nmap -sS -sV -p-`) was run against the Metasploitable target to
simulate the reconnaissance phase of an intrusion. Since Metasploitable doesn't log
incoming connection attempts, evidence was captured on the attacker side with `tcpdump`
instead — a deliberate design choice, documented here rather than treated as a gap.

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Discovery (TA0007) |
| Technique | Network Service Discovery (T1046) |

## Detection Logic

```yaml
detection:
    keywords:
        '|contains': 'SYN'
    condition: keywords

Validation & Conversion
sigma check sigma-rules/portscan_detection.yml
sigma convert -t splunk --without-pipeline sigma-rules/portscan_detection.yml

Splunk Queries

Basic match: "SYN"


Threshold (distinct ports per source — the real scan indicator):


index=detection_lab sourcetype=portscan
| stats dc(dest_port) as unique_ports by src_ip
| where unique_ports > 20

sigma-rules/portscan_detection.yml
splunk/portscan_detection.spl
logs/portscan_nmap_output.txt, logs/portscan_summary_excerpt.log
screenshots/portscan_01_attack_evidence.png
screenshots/portscan_01b_log_conversion.png
screenshots/portscan_02_sigma_rule_validation.png
screenshots/portscan_03_splunk_spl_conversion.png
screenshots/portscan_04_splunk_search_results.png
screenshots/portscan_05_threshold_query_results.png
screenshots/portscan_06_splunk_alert_config.png
screenshots/portscan_07_visualization_bonus.png
