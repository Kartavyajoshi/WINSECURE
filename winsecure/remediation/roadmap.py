"""
WinSecure Remediation Roadmap & Milestone Organizer
"""
from typing import Dict, List
from winsecure.models.remediation import RemediationAction, RemediationPriority


class RoadmapOrganizer:
    """Groups remediation actions into actionable operational time horizons."""

    @staticmethod
    def organize_roadmap(remediations: List[RemediationAction]) -> Dict[str, List[RemediationAction]]:
        roadmap = {
            "Immediate (P0)": [],
            "Within 24 Hours (P1)": [],
            "Within 7 Days (P2)": [],
            "Within 30 Days (P3)": [],
            "Long Term (P4)": [],
        }

        for r in remediations:
            if r.priority == RemediationPriority.P0_IMMEDIATE:
                roadmap["Immediate (P0)"].append(r)
            elif r.priority == RemediationPriority.P1_HIGH:
                roadmap["Within 24 Hours (P1)"].append(r)
            elif r.priority == RemediationPriority.P2_MEDIUM:
                roadmap["Within 7 Days (P2)"].append(r)
            elif r.priority == RemediationPriority.P3_LOW:
                roadmap["Within 30 Days (P3)"].append(r)
            else:
                roadmap["Long Term (P4)"].append(r)

        return roadmap
