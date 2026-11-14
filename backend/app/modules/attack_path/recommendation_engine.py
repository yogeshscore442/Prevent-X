"""
Prevention Recommendation Engine (MOD-03)
Synthesizes and prioritizes compensating controls and mitigations to disrupt attack paths.
Focuses on virtual patching, network segmentation, and service hardening optimized
for SMB operational realities.
"""

from typing import Any, Dict, List, Optional
from backend.app.models.attack_path import (
    ComplexityLevel,
    ImpactLevel,
    RecommendationCategory,
)


class PreventionRecommendationEngine:
    """
    Evaluates attack path choke points and generates ranked compensating controls.
    """

    REDUCTION_SCORES = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    COMPLEXITY_SCORES = {"LOW": 3, "MEDIUM": 2, "HIGH": 1}  # Low complexity = higher rank
    IMPACT_SCORES = {"MINIMAL": 4, "LOW": 3, "MEDIUM": 2, "HIGH": 1}  # Low impact = higher rank

    @classmethod
    def generate_recommendations(
        cls,
        attack_path_id: Any,
        entry_asset: Any,
        target_asset: Any,
        intermediate_assets: List[Any],
        vulnerabilities: List[Any],
        mitre_techniques: List[Dict[str, Any]],
        path_severity: str,
    ) -> List[Dict[str, Any]]:
        """
        Generates actionable, ranked recommendations to break the attack path.
        """
        recs: List[Dict[str, Any]] = []

        # 1. Check for Virtual Patching Opportunities (High priority for SMBs with CVEs)
        for vuln in vulnerabilities:
            cve_id = getattr(vuln, "cve_id", None)
            matched_svc = getattr(vuln, "matched_service_name", "web service")
            if cve_id:
                recs.append({
                    "title": f"Deploy Virtual Patch Rule for {cve_id} on {entry_asset.name}",
                    "category": RecommendationCategory.VIRTUAL_PATCH.value,
                    "target_asset_id": entry_asset.id,
                    "description": (
                        f"Implement a zero-downtime virtual patch rule in front of {matched_svc} on "
                        f"'{entry_asset.name}' to inspect and block malicious payload signatures targeting {cve_id} "
                        f"without modifying application source code."
                    ),
                    "risk_reduction": "HIGH",
                    "implementation_complexity": ComplexityLevel.LOW.value,
                    "smb_operational_impact": ImpactLevel.MINIMAL.value,
                    "mitre_technique_id": "T1190",
                })
                break  # Primary virtual patch for entry

        # 2. Network Segmentation (If intermediate assets or lateral hops exist)
        if intermediate_assets or entry_asset.id != target_asset.id:
            recs.append({
                "title": f"Enforce Network Micro-Segmentation between {entry_asset.name} and {target_asset.name}",
                "category": RecommendationCategory.NETWORK_SEGMENTATION.value,
                "target_asset_id": target_asset.id,
                "description": (
                    f"Restrict inbound connections to crown jewel '{target_asset.name}'. Isolate internal "
                    f"database and backend service ports behind a firewall policy denying direct traffic from "
                    f"DMZ host '{entry_asset.name}'."
                ),
                "risk_reduction": "HIGH",
                "implementation_complexity": ComplexityLevel.MEDIUM.value,
                "smb_operational_impact": ImpactLevel.LOW.value,
                "mitre_technique_id": "T1210",
            })

        # 3. MFA & Remote Access Hardening
        has_remote_svc = any(
            t.get("id") in ("T1133", "T1021.004", "T1021.001") for t in mitre_techniques
        )
        if has_remote_svc:
            recs.append({
                "title": f"Enforce Multi-Factor Authentication (MFA) on {entry_asset.name}",
                "category": RecommendationCategory.MFA_ACCESS_CONTROL.value,
                "target_asset_id": entry_asset.id,
                "description": (
                    f"Mandate MFA and key-based authentication on remote administrative protocols (SSH/RDP) "
                    f"for '{entry_asset.name}', disabling password authentication."
                ),
                "risk_reduction": "HIGH",
                "implementation_complexity": ComplexityLevel.LOW.value,
                "smb_operational_impact": ImpactLevel.LOW.value,
                "mitre_technique_id": "T1133",
            })

        # 4. Service Hardening & Least Privilege
        recs.append({
            "title": f"Harden Service Configurations on {entry_asset.name}",
            "category": RecommendationCategory.SERVICE_HARDENING.value,
            "target_asset_id": entry_asset.id,
            "description": (
                f"Disable unnecessary banners, suppress stack traces, enforce TLS 1.3 with secure ciphers, "
                f"and ensure services run under low-privileged unprivileged service accounts."
            ),
            "risk_reduction": "MEDIUM",
            "implementation_complexity": ComplexityLevel.LOW.value,
            "smb_operational_impact": ImpactLevel.MINIMAL.value,
            "mitre_technique_id": "T1190",
        })

        # 5. Logging and Detection Monitoring
        recs.append({
            "title": f"Enable Centralized Audit & Telemetry Logging for {target_asset.name}",
            "category": RecommendationCategory.LOGGING_MONITORING.value,
            "target_asset_id": target_asset.id,
            "description": (
                f"Configure centralized access and error logging on critical asset '{target_asset.name}' "
                f"to rapidly detect unauthorized queries, administrative logons, or anomalous egress."
            ),
            "risk_reduction": "MEDIUM",
            "implementation_complexity": ComplexityLevel.LOW.value,
            "smb_operational_impact": ImpactLevel.MINIMAL.value,
            "mitre_technique_id": "T1486",
        })

        # Rank recommendations based on combined utility score
        for rec in recs:
            r_score = cls.REDUCTION_SCORES.get(rec["risk_reduction"], 1)
            c_score = cls.COMPLEXITY_SCORES.get(rec["implementation_complexity"], 1)
            i_score = cls.IMPACT_SCORES.get(rec["smb_operational_impact"], 1)
            # Weighted utility: higher reduction + lower complexity + minimal impact
            rec["_rank_score"] = (r_score * 4) + (c_score * 3) + (i_score * 3)
            rec["attack_path_id"] = attack_path_id

        # Sort descending by rank score
        recs.sort(key=lambda x: x["_rank_score"], reverse=True)

        # Assign final 1-based priority rank
        for idx, rec in enumerate(recs, 1):
            rec["priority_rank"] = idx
            rec.pop("_rank_score", None)

        return recs

