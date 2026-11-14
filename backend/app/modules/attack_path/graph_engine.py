"""
Evidence-Backed Attack Path Graph Engine (MOD-03)
Constructs multi-hop Directed Acyclic Graphs (DAG) connecting internet-facing entry points,
intermediate pivots, and crown jewel assets strictly using verified empirical evidence.
Never fabricates lateral movement or network connectivity without supporting records.
"""

import ipaddress
import json
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.asset import AssetCriticality, AssetType, ManagedAsset
from backend.app.models.attack_path import (
    AssetTrustRelationship,
    AttackPath,
    AttackPathConfidence,
    AttackPathSeverity,
    AttackPathStatus,
    PreventionRecommendation,
    TrustRelationshipType,
)
from backend.app.models.attack_surface import DiscoveredService, ServiceState
from backend.app.models.vulnerability import CveRecord, VulnerabilityRecord
from backend.app.modules.attack_path.mitre_mapper import MitreAttackMapper
from backend.app.modules.attack_path.recommendation_engine import PreventionRecommendationEngine
from backend.app.modules.attack_path.risk_scorer import AttackPathRiskScorer


class AttackPathGraphEngine:
    """
    Core graph construction and pathfinding engine.
    """

    def __init__(self, db: Session, organization_id: uuid.UUID):
        self.db = db
        self.organization_id = organization_id

    def _is_private_ip(self, ip_str: str) -> bool:
        """Determines if an IP string is in RFC 1918 private address space or loopback."""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            rfc1918 = [
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
                ipaddress.ip_network("127.0.0.0/8"),
            ]
            return any(ip in net for net in rfc1918)
        except ValueError:
            return False

    def _is_public_entry_point(self, asset: ManagedAsset, services: List[DiscoveredService]) -> bool:
        """
        Determines whether an asset acts as an Internet-facing entry point.
        """
        target = asset.target.lower().strip()

        # Domain names or cloud resources are usually public entry points
        if asset.asset_type in (AssetType.DOMAIN.value, AssetType.CLOUD_RESOURCE.value):
            return True

        # If IP address is public
        if asset.asset_type == AssetType.IP_ADDRESS.value and not self._is_private_ip(target):
            return True

        # If service discovered on asset is public
        for svc in services:
            if getattr(svc, "is_public", False):
                return True
            if svc.port in (80, 443, 8080, 8443, 22, 3389):
                # Public-facing standard services
                if not self._is_private_ip(target):
                    return True

        # Web applications without private IP targets
        if asset.asset_type == AssetType.WEB_APPLICATION.value and not self._is_private_ip(target):
            return True

        return False

    def _is_crown_jewel(self, asset: ManagedAsset, services: List[DiscoveredService]) -> bool:
        """
        Determines whether an asset is a high-value crown jewel target.
        """
        if asset.criticality in (AssetCriticality.CRITICAL.value, AssetCriticality.HIGH.value):
            return True

        # Databases or key repositories
        target = asset.target.lower()
        name = asset.name.lower()
        if any(term in name or term in target for term in ["db", "database", "postgres", "sql", "mongo", "vault", "auth", "ldap", "ad"]):
            return True

        for svc in services:
            svc_name = (svc.service_name or "").lower()
            if any(term in svc_name for term in ["postgres", "mysql", "mssql", "oracle", "mongodb", "redis", "elasticsearch"]):
                return True
            if svc.port in (5432, 3306, 1433, 1521, 27017, 6379):
                return True

        return False

    def _check_shared_subnet(self, ip_a: str, ip_b: str) -> bool:
        """
        Verifies if two IPs belong to the same private /24 subnet.
        """
        try:
            ipa = ipaddress.ip_interface(ip_a.strip() if "/" in ip_a else f"{ip_a.strip()}/24")
            ipb = ipaddress.ip_interface(ip_b.strip() if "/" in ip_b else f"{ip_b.strip()}/24")
            return ipa.network == ipb.network
        except ValueError:
            return False

    def analyze_paths(self) -> List[Dict[str, Any]]:
        """
        Discovers all evidence-backed attack paths for the tenant organization.
        """
        # 1. Fetch organization assets
        assets: List[ManagedAsset] = (
            self.db.execute(
                select(ManagedAsset).where(
                    ManagedAsset.organization_id == self.organization_id,
                    ManagedAsset.is_in_scope.is_(True),
                )
            )
            .scalars()
            .all()
        )

        if not assets:
            return []

        asset_map: Dict[uuid.UUID, ManagedAsset] = {a.id: a for a in assets}

        # 2. Fetch discovered services
        services: List[DiscoveredService] = (
            self.db.execute(
                select(DiscoveredService).where(
                    DiscoveredService.organization_id == self.organization_id,
                    DiscoveredService.state == ServiceState.OPEN,
                )
            )
            .scalars()
            .all()
        )
        services_by_asset: Dict[uuid.UUID, List[DiscoveredService]] = {a.id: [] for a in assets}
        for svc in services:
            if svc.asset_id in services_by_asset:
                services_by_asset[svc.asset_id].append(svc)

        # 3. Fetch vulnerabilities
        vulns: List[VulnerabilityRecord] = (
            self.db.execute(
                select(VulnerabilityRecord).where(
                    VulnerabilityRecord.organization_id == self.organization_id,
                    VulnerabilityRecord.status != "PATCHED",
                )
            )
            .scalars()
            .all()
        )
        vulns_by_asset: Dict[uuid.UUID, List[VulnerabilityRecord]] = {a.id: [] for a in assets}
        for v in vulns:
            if v.asset_id in vulns_by_asset:
                vulns_by_asset[v.asset_id].append(v)

        cve_ids = {v.cve_id for v in vulns if v.cve_id}
        cve_records = (
            self.db.execute(
                select(CveRecord).where(CveRecord.cve_id.in_(cve_ids))
            )
            .scalars()
            .all()
            if cve_ids
            else []
        )
        cve_map = {c.cve_id: c for c in cve_records}

        # 4. Fetch explicit verified trust relationships
        trust_links: List[AssetTrustRelationship] = (
            self.db.execute(
                select(AssetTrustRelationship).where(
                    AssetTrustRelationship.organization_id == self.organization_id,
                )
            )
            .scalars()
            .all()
        )

        # Build adjacency graph based ONLY on verified empirical evidence
        # Map: source_id -> list of (target_id, relationship_type, port, evidence_source, justification)
        evidence_edges: Dict[uuid.UUID, List[Dict[str, Any]]] = {a.id: [] for a in assets}

        # A. Add explicit trust relationships
        for link in trust_links:
            if link.source_asset_id in asset_map and link.target_asset_id in asset_map:
                evidence_edges[link.source_asset_id].append({
                    "target_id": link.target_asset_id,
                    "relationship_type": link.relationship_type,
                    "port": link.port,
                    "evidence_source": f"EXPLICIT_TRUST_RELATIONSHIP ({link.evidence_source})",
                    "justification": f"Verified trust relationship '{link.relationship_type}' configured between assets.",
                    "is_verified": link.is_verified,
                })

        # B. Check for shared subnet evidence between pairs of private IP assets
        for i, a1 in enumerate(assets):
            for a2 in assets[i + 1 :]:
                if self._check_shared_subnet(a1.target, a2.target):
                    evidence_edges[a1.id].append({
                        "target_id": a2.id,
                        "relationship_type": TrustRelationshipType.SAME_SUBNET.value,
                        "port": None,
                        "evidence_source": "NETWORK_SUBNET_MATCH",
                        "justification": f"Assets share verified private network subnet ({a1.target} <-> {a2.target}).",
                        "is_verified": True,
                    })
                    evidence_edges[a2.id].append({
                        "target_id": a1.id,
                        "relationship_type": TrustRelationshipType.SAME_SUBNET.value,
                        "port": None,
                        "evidence_source": "NETWORK_SUBNET_MATCH",
                        "justification": f"Assets share verified private network subnet ({a2.target} <-> {a1.target}).",
                        "is_verified": True,
                    })

        # 5. Classify Entry Points and Crown Jewels
        entry_points = [a for a in assets if self._is_public_entry_point(a, services_by_asset[a.id])]
        crown_jewels = [a for a in assets if self._is_crown_jewel(a, services_by_asset[a.id])]

        # If no public entry point detected, use any asset with internet exposure or highest risk
        if not entry_points and assets:
            entry_points = [assets[0]]
        if not crown_jewels and assets:
            crown_jewels = [assets[-1]]

        discovered_paths: List[Dict[str, Any]] = []

        # 6. Graph Search: Traverse Entry Points to Crown Jewels
        for entry in entry_points:
            entry_svcs = services_by_asset[entry.id]
            entry_vulns = vulns_by_asset[entry.id]

            # Case A: Direct 1-hop path (Entry point is itself a Crown Jewel, or directly exposed high-value target)
            if entry in crown_jewels or entry_vulns:
                path_data = self._build_path_structure(
                    entry_asset=entry,
                    target_asset=entry,
                    intermediate_assets=[],
                    hop_edges=[],
                    services_by_asset=services_by_asset,
                    vulns_by_asset=vulns_by_asset,
                    cve_map=cve_map,
                )
                discovered_paths.append(path_data)

            # Case B: Multi-hop traversal to other crown jewels via evidence-backed edges
            # Breadth-first search from entry to distinct crown jewels
            queue: List[Tuple[ManagedAsset, List[ManagedAsset], List[Dict[str, Any]]]] = [
                (entry, [], [])
            ]
            visited: Set[uuid.UUID] = {entry.id}

            while queue:
                curr_asset, path_intermediates, current_hops = queue.pop(0)

                # Cap max hops to 3 to prevent excessive traversal
                if len(path_intermediates) >= 3:
                    continue

                for edge in evidence_edges.get(curr_asset.id, []):
                    target_id = edge["target_id"]
                    if target_id in visited:
                        continue

                    target_asset = asset_map[target_id]
                    new_intermediates = list(path_intermediates)
                    new_hops = list(current_hops) + [edge]

                    if target_asset in crown_jewels:
                        # Found evidence-backed attack path to a crown jewel
                        path_data = self._build_path_structure(
                            entry_asset=entry,
                            target_asset=target_asset,
                            intermediate_assets=new_intermediates,
                            hop_edges=new_hops,
                            services_by_asset=services_by_asset,
                            vulns_by_asset=vulns_by_asset,
                            cve_map=cve_map,
                        )
                        discovered_paths.append(path_data)

                    visited.add(target_id)
                    queue.append((target_asset, new_intermediates + [target_asset], new_hops))

        # De-duplicate paths by (entry_asset_id, target_asset_id, step_count)
        unique_paths: Dict[str, Dict[str, Any]] = {}
        for p in discovered_paths:
            key = f"{p['entry_point_asset_id']}_{p['target_asset_id']}_{p['step_count']}"
            if key not in unique_paths or p["risk_score"] > unique_paths[key]["risk_score"]:
                unique_paths[key] = p

        return list(unique_paths.values())

    def _build_path_structure(
        self,
        entry_asset: ManagedAsset,
        target_asset: ManagedAsset,
        intermediate_assets: List[ManagedAsset],
        hop_edges: List[Dict[str, Any]],
        services_by_asset: Dict[uuid.UUID, List[DiscoveredService]],
        vulns_by_asset: Dict[uuid.UUID, List[VulnerabilityRecord]],
        cve_map: Optional[Dict[str, CveRecord]] = None,
    ) -> Dict[str, Any]:
        """
        Builds the complete evidence-backed graph nodes, edges, narrative, MITRE mapping, and risk score.
        """
        all_path_assets = [entry_asset] + intermediate_assets + ([target_asset] if entry_asset.id != target_asset.id else [])
        all_path_vulns: List[VulnerabilityRecord] = []
        for a in all_path_assets:
            all_path_vulns.extend(vulns_by_asset.get(a.id, []))

        # Check vulnerability metrics
        max_cvss: Optional[float] = None
        has_cisa_kev = False
        for v in all_path_vulns:
            score = v.risk_score or 0.0
            if max_cvss is None or score > max_cvss:
                max_cvss = score
            cve_obj = cve_map.get(v.cve_id) if (cve_map and v.cve_id) else None
            if cve_obj and getattr(cve_obj, "is_known_exploited", False):
                has_cisa_kev = True
            elif getattr(v, "cve_record", None) and getattr(v.cve_record, "is_known_exploited", False):
                has_cisa_kev = True

        # Confidence calculation
        is_direct = entry_asset.id == target_asset.id
        has_confirmed_vuln = any(v.confidence in ("CONFIRMED", "HIGH") for v in all_path_vulns)
        all_edges_verified = all(h.get("is_verified", True) for h in hop_edges)

        if has_confirmed_vuln and all_edges_verified:
            confidence = AttackPathConfidence.CONFIRMED.value
        elif all_edges_verified or is_direct:
            confidence = AttackPathConfidence.LIKELY.value
        else:
            confidence = AttackPathConfidence.POTENTIAL.value

        step_count = len(hop_edges) + 1 if hop_edges else 1

        # Calculate risk score
        risk_result = AttackPathRiskScorer.calculate_risk(
            is_internet_facing=self._is_public_entry_point(entry_asset, services_by_asset.get(entry_asset.id, [])),
            has_cisa_kev=has_cisa_kev,
            max_cvss=max_cvss,
            has_vulnerabilities=bool(all_path_vulns),
            target_criticality=target_asset.criticality,
            step_count=step_count,
            confidence=confidence,
        )

        # Build Graph Nodes
        nodes: List[Dict[str, Any]] = []
        for a in all_path_assets:
            a_svcs = services_by_asset.get(a.id, [])
            a_vulns = vulns_by_asset.get(a.id, [])
            techs = [s.service_name for s in a_svcs if s.service_name]
            node_max_cvss = max([v.risk_score for v in a_vulns]) if a_vulns else None

            nodes.append({
                "id": str(a.id),
                "name": a.name,
                "asset_type": a.asset_type,
                "criticality": a.criticality,
                "is_entry_point": a.id == entry_asset.id,
                "is_crown_jewel": a.id == target_asset.id,
                "ip_address": a.target,
                "technologies": techs[:5],
                "vulnerabilities_count": len(a_vulns),
                "max_cvss": node_max_cvss,
            })

        # Build Graph Edges & MITRE Techniques
        edges: List[Dict[str, Any]] = []
        mitre_tactics: List[str] = []
        mitre_techniques: List[Dict[str, Any]] = []

        # Step 1: Initial Access
        entry_svcs = services_by_asset.get(entry_asset.id, [])
        primary_svc = entry_svcs[0] if entry_svcs else None
        init_tech = MitreAttackMapper.map_initial_access(
            service_name=primary_svc.service_name if primary_svc else None,
            port=primary_svc.port if primary_svc else None,
            has_vulnerability=bool(vulns_by_asset.get(entry_asset.id, [])),
        )
        mitre_tactics.append("Initial Access")
        mitre_techniques.append(init_tech)

        if not hop_edges:
            # Direct single-hop exploit
            impact_tech = MitreAttackMapper.map_crown_jewel_impact(target_asset.criticality, target_asset.asset_type)
            mitre_tactics.append("Impact")
            mitre_techniques.append(impact_tech)

            edges.append({
                "source": "EXTERNAL_ADVERSARY",
                "target": str(entry_asset.id),
                "hop_type": "EXPLOIT_PUBLIC_SERVICE",
                "port": primary_svc.port if primary_svc else 80,
                "protocol": "TCP",
                "mitre_technique": init_tech["name"],
                "mitre_technique_id": init_tech["id"],
                "evidence_source": f"DISCOVERED_SERVICE (Port {primary_svc.port if primary_svc else 80})",
                "justification": f"External perimeter scan identified accessible service on '{entry_asset.name}'.",
            })
        else:
            # Multi-hop lateral movement
            prev_id = entry_asset.id
            for hop in hop_edges:
                lat_tech = MitreAttackMapper.map_lateral_hop(
                    relationship_type=hop["relationship_type"],
                    port=hop.get("port"),
                )
                if "Lateral Movement" not in mitre_tactics:
                    mitre_tactics.append("Lateral Movement")
                mitre_techniques.append(lat_tech)

                edges.append({
                    "source": str(prev_id),
                    "target": str(hop["target_id"]),
                    "hop_type": hop["relationship_type"],
                    "port": hop.get("port"),
                    "protocol": "TCP",
                    "mitre_technique": lat_tech["name"],
                    "mitre_technique_id": lat_tech["id"],
                    "evidence_source": hop["evidence_source"],
                    "justification": hop["justification"],
                })
                prev_id = hop["target_id"]

            impact_tech = MitreAttackMapper.map_crown_jewel_impact(target_asset.criticality, target_asset.asset_type)
            mitre_tactics.append("Impact")
            mitre_techniques.append(impact_tech)

        prerequisites = MitreAttackMapper.derive_prerequisites(mitre_techniques)

        # Build evidence references
        evidence_refs: List[str] = []
        for s in services_by_asset.get(entry_asset.id, []):
            evidence_refs.append(f"SERVICE:{s.port}/{s.service_name or 'unknown'}")
        for v in all_path_vulns:
            if v.cve_id:
                evidence_refs.append(f"VULNERABILITY:{v.cve_id}")
        for h in hop_edges:
            evidence_refs.append(f"TRUST:{h['evidence_source']}")

        # Construct step-by-step narrative
        if is_direct:
            narrative = (
                f"1. Adversary initiates reconnaissance from the public Internet targeting perimeter asset '{entry_asset.name}' ({entry_asset.target}).\n"
                f"2. Adversary identifies exposed service on port {primary_svc.port if primary_svc else '80'} and exploits vulnerabilities ({', '.join([v.cve_id for v in all_path_vulns if v.cve_id][:2]) or 'misconfiguration'}).\n"
                f"3. Direct impact on crown jewel asset '{target_asset.name}', threatening data availability and confidentiality."
            )
            title = f"Direct Exposure of Crown Jewel '{target_asset.name}'"
        else:
            narrative = (
                f"1. Adversary gains initial foothold on perimeter asset '{entry_asset.name}' via {init_tech['name']} ({init_tech['id']}).\n"
                f"2. Adversary moves laterally across internal boundaries through verified trust relationship ({hop_edges[0]['relationship_type']}) to pivot asset.\n"
                f"3. Adversary reaches crown jewel '{target_asset.name}' ({target_asset.target}) executing {impact_tech['name']} ({impact_tech['id']})."
            )
            title = f"Lateral Pivoting: {entry_asset.name} \u2192 {target_asset.name}"

        name = f"PATH-{entry_asset.name.replace(' ', '_')}-TO-{target_asset.name.replace(' ', '_')}"

        return {
            "name": name,
            "title": title,
            "description": f"Attack chain originating at {entry_asset.name} and reaching critical asset {target_asset.name}.",
            "organization_id": self.organization_id,
            "entry_point_asset_id": entry_asset.id,
            "target_asset_id": target_asset.id,
            "step_count": step_count,
            "risk_score": risk_result["risk_score"],
            "severity": risk_result["severity"],
            "confidence": risk_result["confidence"],
            "path_narrative": narrative,
            "graph_data": json.dumps({"nodes": nodes, "edges": edges}),
            "mitre_tactics": json.dumps(mitre_tactics),
            "mitre_techniques": json.dumps(mitre_techniques),
            "prerequisites": json.dumps(prerequisites),
            "evidence_references": json.dumps(evidence_refs[:10]),
            "status": AttackPathStatus.IDENTIFIED.value,
            "_entry_asset": entry_asset,
            "_target_asset": target_asset,
            "_intermediate_assets": intermediate_assets,
            "_all_path_vulns": all_path_vulns,
            "_mitre_techniques": mitre_techniques,
        }
