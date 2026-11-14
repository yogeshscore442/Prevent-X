"""
MITRE ATT&CK Mapping Module for Attack Path Engine (MOD-03)
Maps discovered attack path hops, vulnerabilities, and services to MITRE ATT&CK
tactics, techniques, and required exploit prerequisites.
"""

from typing import Any, Dict, List, Optional, Tuple


MITRE_TACTICS = {
    "TA0001": {"name": "Initial Access", "description": "Techniques that use various entry vectors to gain an initial foothold."},
    "TA0002": {"name": "Execution", "description": "Techniques that result in adversary-controlled code running on a local or remote system."},
    "TA0003": {"name": "Persistence", "description": "Techniques that adversaries use to keep access across restarts and changed credentials."},
    "TA0004": {"name": "Privilege Escalation", "description": "Techniques that adversaries use to gain higher-level permissions."},
    "TA0005": {"name": "Defense Evasion", "description": "Techniques that adversaries use to avoid detection throughout their compromise."},
    "TA0006": {"name": "Credential Access", "description": "Techniques for stealing credentials like account names and passwords."},
    "TA0007": {"name": "Discovery", "description": "Techniques an adversary may use to gain knowledge about the system and internal network."},
    "TA0008": {"name": "Lateral Movement", "description": "Techniques that adversaries use to enter and control remote systems on a network."},
    "TA0009": {"name": "Collection", "description": "Techniques used to gather information relevant to following the adversary's objectives."},
    "TA0010": {"name": "Exfiltration", "description": "Techniques that adversaries use to steal data from your network."},
    "TA0040": {"name": "Impact", "description": "Techniques used to disrupt availability or compromise integrity by destroying systems and data."},
}

MITRE_TECHNIQUES = {
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic_id": "TA0001",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit vulnerabilities in Internet-facing software to gain initial access.",
        "prerequisites": [
            "Internet-routable IP address or domain",
            "Publicly accessible listening port (HTTP/HTTPS/API)",
            "Unpatched vulnerability or exploitable input validation flaw",
        ],
    },
    "T1133": {
        "id": "T1133",
        "name": "External Remote Services",
        "tactic_id": "TA0001",
        "tactic": "Initial Access",
        "description": "Adversaries may leverage external-facing remote services such as VPNs, SSH, or RDP to access the internal network.",
        "prerequisites": [
            "Exposed remote administration port (e.g. 22/SSH, 3389/RDP)",
            "Single-factor authentication or weak credential policy",
        ],
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic_id": "TA0002",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute arbitrary commands or malicious payloads.",
        "prerequisites": [
            "Arbitrary remote code execution (RCE) primitive",
            "Process execution rights on target host",
        ],
    },
    "T1068": {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic_id": "TA0004",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges from low to root/system.",
        "prerequisites": [
            "Local shell access or low-privileged service execution",
            "Vulnerable kernel version, setuid binary, or unquoted service path",
        ],
    },
    "T1021.004": {
        "id": "T1021.004",
        "name": "Remote Services: SSH",
        "tactic_id": "TA0008",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use SSH to move laterally between hosts inside the private network.",
        "prerequisites": [
            "Direct network route to port 22/tcp between hosts",
            "Compromised SSH private key, password, or trust relationship",
        ],
    },
    "T1021.001": {
        "id": "T1021.001",
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic_id": "TA0008",
        "tactic": "Lateral Movement",
        "description": "Adversaries may log into remote systems using RDP to interact with desktop applications and pivot.",
        "prerequisites": [
            "Network connectivity on TCP port 3389",
            "Valid user or administrator credentials",
        ],
    },
    "T1021.002": {
        "id": "T1021.002",
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic_id": "TA0008",
        "tactic": "Lateral Movement",
        "description": "Adversaries may leverage SMB shares and administrative services to move laterally across workstations and servers.",
        "prerequisites": [
            "SMB port 445/tcp reachable over local subnet",
            "Administrator credentials or NTLM hash",
        ],
    },
    "T1210": {
        "id": "T1210",
        "name": "Exploitation of Remote Services",
        "tactic_id": "TA0008",
        "tactic": "Lateral Movement",
        "description": "Adversaries may exploit remote service vulnerabilities to move laterally through an internal network.",
        "prerequisites": [
            "Reachable internal service port (Database, Redis, RPC, API)",
            "Unpatched remote service vulnerability or missing network micro-segmentation",
        ],
    },
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic_id": "TA0040",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems or attached file shares to interrupt availability and extort ransom.",
        "prerequisites": [
            "Elevated or write privileges on critical data store",
            "Access to unencrypted storage volumes or databases",
        ],
    },
    "T1485": {
        "id": "T1485",
        "name": "Data Destruction",
        "tactic_id": "TA0040",
        "tactic": "Impact",
        "description": "Adversaries may destroy data and software on systems to disrupt operations or conceal evidence.",
        "prerequisites": [
            "Administrative privileges on database or filesystem",
        ],
    },
    "T1041": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic_id": "TA0010",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal sensitive records, financial files, or proprietary schemas over outbound connections.",
        "prerequisites": [
            "Outbound network egress permitted",
            "Read access to sensitive database tables or file assets",
        ],
    },
}


class MitreAttackMapper:
    """
    Analyzes graph hops and maps them to MITRE ATT&CK Tactics & Techniques.
    """

    @classmethod
    def get_technique(cls, technique_id: str) -> Optional[Dict[str, Any]]:
        return MITRE_TECHNIQUES.get(technique_id)

    @classmethod
    def map_initial_access(
        cls,
        service_name: Optional[str] = None,
        port: Optional[int] = None,
        has_vulnerability: bool = True,
    ) -> Dict[str, Any]:
        """Maps internet-facing service exposure to Initial Access techniques."""
        port_num = port or 0
        svc = (service_name or "").lower()

        if port_num in (22, 3389, 5900) or any(x in svc for x in ["ssh", "rdp", "vnc", "vpn"]):
            return MITRE_TECHNIQUES["T1133"]  # External Remote Services

        # Default for web, API, or general exploitable services
        return MITRE_TECHNIQUES["T1190"]  # Exploit Public-Facing Application

    @classmethod
    def map_lateral_hop(
        cls,
        relationship_type: str,
        port: Optional[int] = None,
        target_service: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Maps trust or network hops between assets to Lateral Movement techniques."""
        port_num = port or 0
        rel = relationship_type.upper()
        svc = (target_service or "").lower()

        if "SSH" in rel or port_num == 22 or "ssh" in svc:
            return MITRE_TECHNIQUES["T1021.004"]
        elif "RDP" in rel or port_num == 3389 or "rdp" in svc:
            return MITRE_TECHNIQUES["T1021.001"]
        elif port_num == 445 or "smb" in svc or "ad" in svc or "ACTIVE_DIRECTORY" in rel:
            return MITRE_TECHNIQUES["T1021.002"]
        else:
            return MITRE_TECHNIQUES["T1210"]  # Exploitation of Remote Services

    @classmethod
    def map_crown_jewel_impact(
        cls,
        target_asset_criticality: str,
        target_type: str,
    ) -> Dict[str, Any]:
        """Maps target crown jewel impact to Impact techniques."""
        if target_asset_criticality.upper() in ("CRITICAL", "HIGH"):
            return MITRE_TECHNIQUES["T1486"]  # Ransomware / Data Encrypted for Impact
        return MITRE_TECHNIQUES["T1041"]  # Exfiltration

    @classmethod
    def derive_prerequisites(cls, techniques: List[Dict[str, Any]]) -> List[str]:
        """Extracts unique prerequisite requirements for an attack chain."""
        prereqs: List[str] = []
        for tech in techniques:
            for req in tech.get("prerequisites", []):
                if req not in prereqs:
                    prereqs.append(req)
        return prereqs
