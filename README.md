# Cybersecurity Home Lab (Threat Hunting + SIEM)

## Overview
This project documents my cybersecurity home lab where I built a Windows Active Directory environment integrated with Splunk SIEM to simulate real-world security monitoring and threat hunting scenarios.

The goal of this lab was to move beyond basic logging and practice hypothesis-driven threat hunting, detection development, and analysis of endpoint telemetry similar to a SOC environment like SentinelOne.

---

## Lab Environment
- Windows Server VM: Active Directory Domain Controller  
- Windows Client VM: Domain-joined endpoint  
- Splunk Enterprise: SIEM (log ingestion + analysis)  
- Splunk Universal Forwarder: Sends Windows logs to Splunk  
- Tools: Wireshark, Nmap, Windows Event Viewer  

---

## Network Setup
- Logs forwarded to Splunk on port 9997  
- Virtualized lab network for controlled attack simulation  
- Endpoint telemetry collected from Windows machines  

---

## What I Configured
- Installed and configured Splunk Enterprise as a SIEM  
- Enabled log ingestion on port 9997  
- Deployed Splunk Universal Forwarder on endpoints  
- Centralized Windows Event Logs into Splunk  
- Built queries to analyze authentication and process activity  

---

## Threat Hunting Approach
Instead of only monitoring logs, I practiced threat hunting using a hypothesis-based approach:

Example hypotheses:
- Multiple failed logins followed by a success may indicate brute force activity  
- Unusual PowerShell execution could indicate living-off-the-land techniques  
- Unexpected network scanning behavior may indicate reconnaissance  

I then used Splunk to test these hypotheses against collected endpoint logs.

---

## Detections & Analysis
- Event ID 4624 (Successful logons)  
- Failed authentication attempts  
- PowerShell activity monitoring  
- Reconnaissance detection using Nmap scans  
- Packet-level inspection with Wireshark  

Example Splunk query:
```spl
index=wineventlog EventCode=4624
