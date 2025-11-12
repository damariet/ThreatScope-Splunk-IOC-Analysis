# ThreatScope: Splunk IOC Correlation and Host Analysis

### 📖 Overview
ThreatScope is a cybersecurity monitoring exercise that demonstrates how Splunk can be used as a Security Information and Event Management (SIEM) tool to identify and correlate Indicators of Compromise (IOCs) across simulated network traffic.  

In this project, I analyzed network proxy logs and known malicious IPs associated with the SolarWinds breach to detect compromised hosts and document threat patterns.

---

### 🎯 Objectives
- Ingest IOC and network log data into Splunk.
- Correlate known malicious IPs against internal traffic data.
- Identify impacted systems and log timestamps.
- Build a dashboard to automate future IOC monitoring.

---

### 🔍 Core Splunk Query
```spl
source="SolarWindsIOCs.csv" OR source="NetworkProxyLog02.csv"
| stats values(source) as Source, values("Computer Name") as ComputerName, values(Date) as Date, values(Time) as Time by "IP Address"
| where mvcount(Source) > 1
| table "IP Address", ComputerName, Date, Time

