# Automated Threat Intelligence & IoC Triage Engine

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Domain: Threat Intel](https://img.shields.io/badge/Domain-Threat%20Intelligence-purple.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **An automated Indicator of Compromise (IoC) triage pipeline that ingests unvetted network indicators (IPs, URLs, Domains), categorizes confidence levels, isolates RFC 1918 private subnets, and automates blocking decisions for Security Operations Centers.**

---

## 🏗️ Architecture

```text
                  Incoming Raw IoCs
                (IPs, Domains, Hashes)
                          │
                          ▼
             [ Indicator Normalization ]
                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
   RFC 1918 Filter    Known Whitelist   Reputation & Threat Feeds
   (Local Subnets)    (Benign Traffic)  (Confidence Scoring)
         │                │                │
         ▼                ▼                ▼
      [IGNORE]         [ALLOW]     [BLOCK & ISOLATE]
```

---

## 🚀 Quickstart

```bash
git clone https://github.com/enggr-bilal/threat-intel-lookup.git
cd threat-intel-lookup

python3 src/threat_intel.py --file data/iocs.txt
```

---

## 👨‍💻 Author
**Muhammad Bilal** — Cybersecurity Engineer & Data Scientist
