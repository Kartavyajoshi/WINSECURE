"""
WinSecure SARIF (OASIS Static Analysis Results Interchange Format) Exporter
"""
import json
import os
from typing import Any, Dict
from winsecure.models.scan import ScanResult


class SarifExporter:
    """Exports findings into standard SARIF v2.1.0 format for CI/CD & GitHub Security."""

    @staticmethod
    def export(result: ScanResult, output_dir: str) -> str:
        sarif_path = os.path.join(output_dir, "data", "results.sarif")
        os.makedirs(os.path.dirname(sarif_path), exist_ok=True)

        rules_list = []
        results_list = []

        for f in result.findings:
            rule_id = f.id
            rule_entry = {
                "id": rule_id,
                "name": f.title.replace(" ", "_"),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {
                    "text": f"{f.description}\n\nExpected: {f.expected}\nActual: {f.actual}\nRemediation: {f.remediation}",
                    "markdown": f"### {f.title}\n\n{f.description}\n\n* **Expected**: `{f.expected}`\n* **Actual**: `{f.actual}`\n\n#### Remediation\n{f.remediation}"
                },
                "properties": {
                    "category": f.category,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "compliance": f.compliance,
                    "mitre_attack": f.mitre_attack,
                }
            }
            rules_list.append(rule_entry)

            # Map severity to SARIF level
            level = "error" if f.severity.value in ["Critical", "High"] else ("warning" if f.severity.value == "Medium" else "note")
            if f.status.value == "FAIL":
                res_entry = {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {
                        "text": f"{f.title}: Observed '{f.actual}', expected '{f.expected}'."
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": f"windows://{f.category.lower().replace(' ', '_')}"
                                },
                                "region": {
                                    "startLine": 1,
                                    "startColumn": 1
                                }
                            }
                        }
                    ],
                    "properties": {
                        "confidence": f.confidence,
                        "remediation": f.remediation,
                    }
                }
                results_list.append(res_entry)

        sarif_payload = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "WinSecure",
                            "version": result.winsecure_version,
                            "informationUri": "https://github.com/Kartavyajoshi/WINSECURE",
                            "rules": rules_list
                        }
                    },
                    "results": results_list,
                    "invocations": [
                        {
                            "executionSuccessful": len(result.errors) == 0,
                            "endTimeUtc": result.timestamp
                        }
                    ]
                }
            ]
        }

        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(sarif_payload, f, indent=2)

        return sarif_path
