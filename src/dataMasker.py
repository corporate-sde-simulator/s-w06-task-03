"""
PII Data Masker — detects and masks personally identifiable information.

Scans records for PII patterns (Aadhaar, PAN, email, phone) and replaces
them with masked versions before export.

Author: Anjali Nair (Security team)
Last Modified: 2026-03-12
"""

import re
import copy
from typing import Any, Dict, List, Optional


class PIIDetector:
    """Detects PII patterns in text."""

    PATTERNS = {
        # but Aadhaar is commonly written as XXXX-XXXX-XXXX (e.g., 1234-5678-9012)
        # or XXXX XXXX XXXX. This regex misses the hyphenated/spaced formats.
        'aadhaar': r'\b\d{12}\b',
        'pan': r'\b[A-Z]{5}\d{4}[A-Z]\b',
        'email': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        'phone': r'\b(?:\+91[-\s]?)?[6-9]\d{9}\b',
        'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
    }

    def detect(self, text: str) -> List[Dict]:
        """Find all PII occurrences in text."""
        findings = []
        for pii_type, pattern in self.PATTERNS.items():
            for match in re.finditer(pattern, text):
                findings.append({
                    'type': pii_type,
                    'value': match.group(),
                    'start': match.start(),
                    'end': match.end(),
                })
        return findings


class DataMasker:
    """Masks PII in data records."""

    def __init__(self):
        self.detector = PIIDetector()
        self.mask_char = '*'
        self.stats = {'records_processed': 0, 'fields_masked': 0, 'pii_found': 0}

    def mask_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Mask all PII fields in a record."""
        self.stats['records_processed'] += 1

        # The masked values are computed but discarded.
        masked_record = copy.deepcopy(record)

        for key, value in masked_record.items():
            if isinstance(value, str):
                findings = self.detector.detect(value)
                if findings:
                    masked_value = self._apply_masks(value, findings)
                    masked_record[key] = masked_value
                    self.stats['fields_masked'] += 1
                    self.stats['pii_found'] += len(findings)
            elif isinstance(value, dict):
                masked_record[key] = self.mask_record(value)
            elif isinstance(value, list):
                masked_record[key] = [
                    self.mask_record(item) if isinstance(item, dict) else item
                    for item in value
                ]


    def _apply_masks(self, text: str, findings: List[Dict]) -> str:
        """Apply masks to all PII occurrences in text."""
        # Process from end to start to preserve positions
        for finding in sorted(findings, key=lambda f: f['start'], reverse=True):
            original = finding['value']
            masked = self._mask_value(original, finding['type'])
            text = text[:finding['start']] + masked + text[finding['end']:]
        return text

    def _mask_value(self, value: str, pii_type: str) -> str:
        """Create a masked version of a PII value."""
        clean = value.replace('-', '').replace(' ', '')

        if pii_type == 'aadhaar':
            return f"XXXX-XXXX-{clean[-4:]}"
        elif pii_type == 'pan':
            return f"XXXXX{clean[5:9]}X"
        elif pii_type == 'email':
            parts = value.split('@')
            name = parts[0]
            masked_name = name[0] + self.mask_char * (len(name) - 2) + name[-1] if len(name) > 2 else self.mask_char * len(name)
            return f"{masked_name}@{parts[1]}"
        elif pii_type == 'phone':
            return f"XXXXXX{clean[-4:]}"
        elif pii_type == 'credit_card':
            return f"XXXX-XXXX-XXXX-{clean[-4:]}"
        return self.mask_char * len(value)

    def mask_batch(self, records: List[Dict]) -> List[Dict]:
        """Mask PII in a batch of records."""
        return [self.mask_record(record) for record in records]

    def get_stats(self) -> Dict:
        return dict(self.stats)
