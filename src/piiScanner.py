"""
PII Scanner — scans database tables for PII and generates compliance reports.

Author: Anjali Nair (Security team)
Last Modified: 2026-03-12
"""

from typing import Dict, List, Optional


class PIIScanner:
    """Scans records and generates PII compliance reports."""

    def __init__(self, masker):
        self.masker = masker
        self.scan_results: List[Dict] = []

    def scan_table(self, table_name: str, records: List[Dict]) -> Dict:
        """Scan a table of records for PII."""
        pii_fields = set()
        pii_records = 0

        for record in records:
            record_has_pii = False
            for key, value in record.items():
                if isinstance(value, str):
                    findings = self.masker.detector.detect(value)
                    if findings:
                        pii_fields.add(key)
                        record_has_pii = True

            if record_has_pii:
                pii_records += 1

        result = {
            'table': table_name,
            'total_records': len(records),
            'records_with_pii': pii_records,
            'pii_fields': list(pii_fields),
            'pii_percentage': round(pii_records / max(len(records), 1) * 100, 2),
        }

        self.scan_results.append(result)
        return result

    def generate_compliance_report(self) -> Dict:
        """Generate a compliance summary report."""
        total_tables = len(self.scan_results)
        tables_with_pii = [r for r in self.scan_results if r['records_with_pii'] > 0]

        return {
            'total_tables_scanned': total_tables,
            'tables_with_pii': len(tables_with_pii),
            'high_risk_tables': [r['table'] for r in tables_with_pii if r['pii_percentage'] > 50],
            'medium_risk_tables': [r['table'] for r in tables_with_pii if 10 < r['pii_percentage'] <= 50],
            'low_risk_tables': [r['table'] for r in tables_with_pii if r['pii_percentage'] <= 10],
            'details': self.scan_results,
        }
