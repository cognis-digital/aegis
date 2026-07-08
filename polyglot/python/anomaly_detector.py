import os
import re
from typing import List, Dict, Any
import json
import hashlib
from datetime import datetime, timedelta
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AnomalyDetector:
    def __init__(self):
        self.credentials_pattern = re.compile(r'((?:password|token|secret|key)=["\']?([^"\'\s,]+)["\']?)')
        self.injection_patterns = [
            re.compile(r'(\bAND\b|\bOR\b|\bWHERE\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bTRUNCATE\b|\bEXEC\b|\bUNION\b)'),
            re.compile(r'(\b[\'\"\;\(\)]+|\b--|\b#|\b--|\b/*|\b//|\b%|\b_|\b\*|\b=|\b!=|\b<>|\b<|\b>|\b<=|\b>=|\b&&|\b||)'),
            re.compile(r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)')
        ]
        self.reach_patterns = [
            re.compile(r'(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)')
        ]
        self.anomalies = []

    def detect_credentials(self, text: str) -> List[str]:
        matches = self.credentials_pattern.findall(text)
        return [f"Potential credential found: {match[1]}" for match in matches]

    def detect_injections(self, text: str) -> List[str]:
        anomalies = []
        for pattern in self.injection_patterns:
            for match in pattern.finditer(text):
                anomalies.append(f"Potential injection detected: {match.group(0)}")
        return anomalies

    def detect_reach(self, text: str) -> List[str]:
        anomalies = []
        for pattern in self.reach_patterns:
            for match in pattern.finditer(text):
                anomalies.append(f"Potential reach detected: {match.group(0)}")
        return anomalies

    def analyze(self, text: str) -> Dict[str, List[str]]:
        self.anomalies = []
        self.anomalies.extend(self.detect_credentials(text))
        self.anomalies.extend(self.detect_injections(text))
        self.anomalies.extend(self.detect_reach(text))
        return {
            "anomalies": self.anomalies,
            "timestamp": datetime.now().isoformat()
        }

def main():
    # Example input text for demonstration
    sample_text = """
    User login: username='admin', password='s3cr3t123'
    Query: SELECT * FROM users WHERE id = 1 OR '1' = '1'
    API call to http://api.example.com/data?token=abc123
    """

    detector = AnomalyDetector()
    result = detector.analyze(sample_text)
    print("Anomaly Detection Results:")
    for anomaly in result["anomalies"]:
        print(f" - {anomaly}")
    print(f"\nTimestamp: {result['timestamp']}")

if __name__ == "__main__":
    main()