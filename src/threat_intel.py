#!/usr/bin/env python3
"""
Automated Threat Intelligence IoC Triage Engine
Author: Muhammad Bilal
"""

import ipaddress
import argparse
import json
import re

# Mock offline Threat Intelligence feed for reliable zero-token testing
KNOWN_MALICIOUS_DB = {
    "185.220.101.5": {"confidence": 98, "category": "Tor Exit Node / Scanner", "threat_level": "CRITICAL"},
    "194.26.29.112": {"confidence": 92, "category": "Cobalt Strike C2", "threat_level": "HIGH"},
    "malicious-c2-update.com": {"confidence": 95, "category": "Malware C2 Domain", "threat_level": "HIGH"},
    "verify-bank-security-login.xyz": {"confidence": 99, "category": "Phishing / Credential Harvesting", "threat_level": "CRITICAL"}
}

KNOWN_BENIGN_WHITELIST = {"8.8.8.8", "1.1.1.1", "google.com", "microsoft.com"}

class ThreatIntelTriage:
    def __init__(self, ioc_file):
        self.ioc_file = ioc_file
        self.results = []

    def classify_indicator(self, indicator):
        indicator = indicator.strip()
        if not indicator or indicator.startswith('#'):
            return None

        # Check for RFC 1918 Private IP
        try:
            ip = ipaddress.ip_address(indicator)
            if ip.is_private:
                return {
                    "indicator": indicator,
                    "type": "IPv4",
                    "status": "INTERNAL",
                    "risk_score": 0,
                    "category": "RFC 1918 Private Network (Local)",
                    "action": "IGNORE"
                }
        except ValueError:
            pass

        # Whitelist check
        if indicator in KNOWN_BENIGN_WHITELIST:
            return {
                "indicator": indicator,
                "type": "IP/Domain",
                "status": "BENIGN",
                "risk_score": 0,
                "category": "Known Trusted Entity",
                "action": "ALLOW"
            }

        # Threat Database check
        if indicator in KNOWN_MALICIOUS_DB:
            intel = KNOWN_MALICIOUS_DB[indicator]
            return {
                "indicator": indicator,
                "type": "IP/Domain",
                "status": "MALICIOUS",
                "risk_score": intel["confidence"],
                "category": intel["category"],
                "action": "BLOCK & ISOLATE"
            }

        # Unknown / Suspicious domain heuristics
        if indicator.endswith(('.xyz', '.top', '.tk', '.cc')):
            return {
                "indicator": indicator,
                "type": "Domain",
                "status": "SUSPICIOUS",
                "risk_score": 75,
                "category": "High-Risk Top Level Domain (TLD)",
                "action": "FLAG FOR ANALYST"
            }

        return {
            "indicator": indicator,
            "type": "IP/Domain",
            "status": "UNKNOWN",
            "risk_score": 15,
            "category": "Unrated Indicator",
            "action": "MONITOR"
        }

    def triage(self):
        with open(self.ioc_file, 'r', encoding='utf-8') as f:
            for line in f:
                res = self.classify_indicator(line)
                if res:
                    self.results.append(res)
        return self.results

    def print_summary(self):
        print("=" * 75)
        print(" THREAT INTELLIGENCE IOC TRIAGE CONSOLE")
        print("=" * 75)
        print(f"{'INDICATOR':<32} | {'STATUS':<10} | {'RISK':<5} | {'RECOMMENDED ACTION'}")
        print("-" * 75)
        for r in self.results:
            color = "[!]" if r["status"] == "MALICIOUS" else "[*]" if r["status"] == "SUSPICIOUS" else "[-]"
            print(f"{r['indicator']:<32} | {r['status']:<10} | {r['risk_score']:<5} | {r['action']}")
        print("=" * 75)

def main():
    parser = argparse.ArgumentParser(description="Automated Threat Intelligence IoC Triage")
    parser.add_argument("--file", default="../data/iocs.txt", help="Path to indicator list")
    args = parser.parse_args()

    triage = ThreatIntelTriage(args.file)
    triage.triage()
    triage.print_summary()

if __name__ == "__main__":
    main()
