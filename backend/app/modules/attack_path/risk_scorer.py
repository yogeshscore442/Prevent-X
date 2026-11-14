"""
Attack Path Risk Scoring Engine (MOD-03)
Strict 0-100 contextual risk calculation combining entry-point exposure,
vulnerability exploitability (CVSS/KEV), crown jewel target criticality,
path complexity, and evidence confidence.
"""

from typing import Any, Dict, List, Optional
from backend.app.models.attack_path import AttackPathConfidence, AttackPathSeverity


class AttackPathRiskScorer:
    """
    Computes evidence-backed contextual risk scores for attack paths on a strict 0-100 scale.
    """

    MAX_ENTRY_EXPOSURE_POINTS = 25.0
    MAX_VULNERABILITY_POINTS = 35.0
    MAX_TARGET_CRITICALITY_POINTS = 25.0
    MAX_FEASIBILITY_POINTS = 15.0

    CONFIDENCE_WEIGHTS = {
        AttackPathConfidence.CONFIRMED.value: 1.0,
        AttackPathConfidence.LIKELY.value: 0.85,
        AttackPathConfidence.POTENTIAL.value: 0.60,
    }

    @classmethod
    def calculate_risk(
        cls,
        is_internet_facing: bool,
        has_cisa_kev: bool,
        max_cvss: Optional[float],
        has_vulnerabilities: bool,
        target_criticality: str,
        step_count: int,
        confidence: str = AttackPathConfidence.POTENTIAL.value,
    ) -> Dict[str, Any]:
        """
        Calculates normalized risk score and full breakdown.
        """
        # 1. Entry-point exposure (0-25 pts)
        if is_internet_facing:
            if has_cisa_kev:
                entry_points = 25.0
            else:
                entry_points = 18.0
        else:
            entry_points = 8.0

        # 2. Maximum vulnerability severity along path (0-35 pts)
        cvss = max_cvss or 0.0
        if not has_vulnerabilities:
            vuln_points = 5.0  # Inherent exposure without confirmed CVE
        elif has_cisa_kev or cvss >= 9.0:
            vuln_points = 35.0
        elif cvss >= 7.0:
            vuln_points = 25.0
        elif cvss >= 4.0:
            vuln_points = 15.0
        else:
            vuln_points = 8.0

        # 3. Crown Jewel target criticality (0-25 pts)
        crit = (target_criticality or "MEDIUM").upper()
        if crit == "CRITICAL":
            crit_points = 25.0
        elif crit == "HIGH":
            crit_points = 18.0
        elif crit == "MEDIUM":
            crit_points = 10.0
        else:
            crit_points = 5.0

        # 4. Path feasibility & simplicity (0-15 pts)
        # Direct paths are easier for attackers to traverse (fewer perimeter boundaries to bypass)
        if step_count <= 1:
            feasibility_points = 15.0
        elif step_count == 2:
            feasibility_points = 12.0
        elif step_count == 3:
            feasibility_points = 8.0
        else:
            feasibility_points = 5.0

        raw_score = entry_points + vuln_points + crit_points + feasibility_points
        # Mathematical bound guarantee
        raw_score = min(100.0, max(0.0, raw_score))

        # Confidence scaling
        conf_multiplier = cls.CONFIDENCE_WEIGHTS.get(
            confidence.upper(), AttackPathConfidence.POTENTIAL.value
        )
        if isinstance(conf_multiplier, str):
            conf_multiplier = 0.60

        final_score = round(min(100.0, max(0.0, raw_score * conf_multiplier)), 1)

        # Severity categorization
        if final_score >= 80.0:
            severity = AttackPathSeverity.CRITICAL.value
        elif final_score >= 60.0:
            severity = AttackPathSeverity.HIGH.value
        elif final_score >= 35.0:
            severity = AttackPathSeverity.MEDIUM.value
        else:
            severity = AttackPathSeverity.LOW.value

        return {
            "risk_score": final_score,
            "severity": severity,
            "confidence": confidence,
            "breakdown": {
                "entry_exposure_points": entry_points,
                "vulnerability_points": vuln_points,
                "target_criticality_points": crit_points,
                "feasibility_points": feasibility_points,
                "raw_total": raw_score,
                "confidence_multiplier": conf_multiplier,
            },
        }

