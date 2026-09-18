"""
WinSecure SIEM Exporters
Exports scan findings into vendor formats for Splunk (HEC), Elastic (ECS),
and Microsoft Sentinel (ASIM-style) ingestion pipelines.
"""
import json
import os
from typing import Any, Dict, List, Optional
from winsecure.models.scan import ScanResult


class SiemExporter:
    """Exports findings into SIEM-ready NDJSON payloads for multiple vendors."""

    SUPPORTED_PLATFORMS = ("splunk", "elastic", "sentinel")

    @staticmethod
    def resolve_platforms(choice: str = "all") -> List[str]:
        """Maps a CLI choice (platform name or 'all') onto supported platforms."""
        choice = (choice or "all").lower().strip()
        if choice == "all":
            return list(SiemExporter.SUPPORTED_PLATFORMS)
        return [choice] if choice in SiemExporter.SUPPORTED_PLATFORMS else []

    @staticmethod
    def export(result: ScanResult, output_dir: str, platform: str = "splunk") -> Optional[str]:
        """Writes a platform-specific NDJSON file; returns the written path."""
        platform = platform.lower().strip()
        if platform not in SiemExporter.SUPPORTED_PLATFORMS:
            return None

        if platform == "splunk":
            events = SiemExporter.to_splunk_events(result)
        elif platform == "elastic":
            events = SiemExporter.to_elastic_events(result)
        else:
            events = SiemExporter.to_sentinel_events(result)

        out_path = os.path.join(output_dir, "siem", f"findings_{platform}.ndjson")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        with open(out_path, "w", encoding="utf-8") as fh:
            for event in events:
                fh.write(json.dumps(event, default=str) + "\n")
        return out_path

    @staticmethod
    def export_all_platforms(result: ScanResult, output_dir: str) -> Dict[str, Optional[str]]:
        """Exports NDJSON for every supported SIEM platform."""
        return {
            platform: SiemExporter.export(result, output_dir, platform)
            for platform in SiemExporter.SUPPORTED_PLATFORMS
        }

    # ------------------------------------------------------------------
    # Shared event scaffolding
    # ------------------------------------------------------------------

    @staticmethod
    def _base_event(result: ScanResult, ecs_category: str) -> Dict[str, Any]:
        """Common envelope fields shared by all SIEM event formats."""
        inventory = result.inventory
        return {
            "@timestamp": result.timestamp,
            "event.kind": "alert",
            "event.category": ecs_category,
            "event.type": "info",
            "event.module": "winsecure",
            "event.dataset": "winsecure.assessment",
            "winsecure.scan_id": result.scan_id,
            "winsecure.version": result.winsecure_version,
            "winsecure.profile": result.profile,
            "winsecure.security_score": result.security_score,
            "winsecure.risk_level": result.risk_level.value if hasattr(result.risk_level, "value") else str(result.risk_level),
            "host.hostname": inventory.hostname if inventory else "unknown",
            "host.os.name": inventory.os_name if inventory else "Windows",
            "host.os.version": inventory.os_build if inventory else "unknown",
        }

    @staticmethod
    def _finding_fields(finding_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts normalized finding fields shared across formats."""
        return {
            "winsecure.finding_id": finding_dict.get("id"),
            "winsecure.title": finding_dict.get("title"),
            "winsecure.category": finding_dict.get("category"),
            "winsecure.severity": finding_dict.get("severity"),
            "winsecure.status": finding_dict.get("status"),
            "message": (
                f"{finding_dict.get('title')}: observed "
                f"'{finding_dict.get('actual')}', expected '{finding_dict.get('expected')}'"
            ),
        }

    @staticmethod
    def _failed_findings(result: ScanResult) -> List[Dict[str, Any]]:
        """Returns dict form of FAIL/WARN findings only."""
        return [
            f.to_dict() for f in result.findings
            if f.status.value in ("FAIL", "WARN")
        ]

    # ------------------------------------------------------------------
    # Platform-specific transforms
    # ------------------------------------------------------------------

    @staticmethod
    def to_splunk_events(result: ScanResult) -> List[Dict[str, Any]]:
        """Splunk HEC JSON events (sourcetype=winsecure:assessment)."""
        events = []
        for f in SiemExporter._failed_findings(result):
            event = SiemExporter._base_event(result, "configuration")
            event.update(SiemExporter._finding_fields(f))
            event["sourcetype"] = "winsecure:assessment"
            event["index"] = "winsecure"
            event["remediation"] = f.get("remediation")
            event["impact"] = f.get("impact")
            events.append(event)
        return events

    @staticmethod
    def to_elastic_events(result: ScanResult) -> List[Dict[str, Any]]:
        """Elastic Common Schema (ECS) compliant events."""
        severity_ecs_map = {
            "Critical": 9, "High": 7, "Medium": 5, "Low": 3, "Informational": 1,
        }
        status_map = {"FAIL": "failure", "WARN": "warning"}

        events = []
        for f in SiemExporter._failed_findings(result):
            event = SiemExporter._base_event(result, "configuration")
            event.update(SiemExporter._finding_fields(f))
            event["event.severity"] = severity_ecs_map.get(f.get("severity"), 1)
            event["event.outcome"] = status_map.get(f.get("status"), "unknown")
            event["rule.id"] = f.get("id")
            event["rule.name"] = f.get("title")
            event["rule.category"] = f.get("category")
            event["tags"] = ["winsecure", "compliance", (f.get("category") or "general").lower()]
            events.append(event)
        return events

    @staticmethod
    def to_sentinel_events(result: ScanResult) -> List[Dict[str, Any]]:
        """Microsoft Sentinel / ASIM-aligned events (TimeGenerated based)."""
        sentinel_severity_map = {
            "Critical": "High", "High": "High", "Medium": "Medium",
            "Low": "Low", "Informational": "Informational",
        }
        events = []
        for f in SiemExporter._failed_findings(result):
            event = SiemExporter._base_event(result, "SecurityAssessment")
            event.update(SiemExporter._finding_fields(f))
            event["TimeGenerated"] = result.timestamp
            event["Severity"] = sentinel_severity_map.get(f.get("severity"), "Low")
            event["Computer"] = event.pop("host.hostname", "unknown")
            event["Description"] = f.get("description")
            event["RemediationSteps"] = f.get("remediation")
            event["Recommendation"] = f.get("expected")
            events.append(event)
        return events
