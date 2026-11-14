# Future Modules Architecture & Extension Points

PREVENT-X defines 12 modular cybersecurity engines. In **Phase 1**, the software foundation, multi-tenant boundaries, and common module interfaces are established. Subsequent engines will be activated in later phases according to the roadmap below.

---

## 1. Module Inventory & Status

| Module ID | Module Title | Target Phase | Phase 1 Status | Scope & Boundary |
|:---|:---|:---:|:---:|:---|
| **MOD-01** | Attack Surface Intelligence Engine | Phase 2 | Architectural Stub | External asset discovery, subdomain enumeration, port & service fingerprinting for authorized SMB assets. |
| **MOD-02** | Advanced Vulnerability Mapping Engine | Phase 3 | Architectural Stub | Mapping NVD / CVE feeds and CWE weaknesses against detected asset software components. |
| **MOD-03** | Attack Path & Prerequisite Analysis | Phase 4 | Architectural Stub | Graph analysis of multi-step kill chains, privilege escalation paths, and lateral movement prerequisites. |
| **MOD-04** | Zero Trust Security Engine | Phase 4 | Architectural Stub | Micro-segmentation policy generation, mutual TLS, and continuous verification gates. |
| **MOD-05** | AI Threat Intelligence Engine | Phase 5 | Architectural Stub | Threat actor profiling, real-time IoC correlation, and contextual risk scoring for Indian SMBs. |
| **MOD-06** | Proactive Security Hardening Engine | Phase 5 | Architectural Stub | Automated configuration baseline audit (CIS Benchmarks), HTTP header compliance, and attack surface reduction. |
| **MOD-07** | Zero-Day & Unknown Threat Protection | Phase 6 | Architectural Stub | Anomaly detection, behavioral inspection, and payload heuristic filters. |
| **MOD-08** | Intelligent Virtual Patching Engine | Phase 6 | Architectural Stub | Core PS-05 engine: Synthesizes precise compensating security rules (WAF/Envoy/ModSecurity/eBPF) without code changes. |
| **MOD-09** | Real-Time Traffic Monitoring Engine | Phase 7 | Architectural Stub | High-throughput packet and flow inspection, telemetry aggregation, and policy hit analysis. |
| **MOD-10** | Automated Security Validation Engine | Phase 7 | Architectural Stub | Safe pre-deployment replay of benign vs exploit payloads to guarantee zero false-blocks. |
| **MOD-11** | Automated Response & Reliable Rollback | Phase 8 | Architectural Stub | Instant automated rollback and atomic rule reversion if service degradation or false-positives occur. |
| **MOD-12** | Centralized SMB Management Platform | Phase 1 | **OPERATIONAL** | Multi-tenant tenant onboarding, user RBAC, asset inventory, system health telemetry, and immutable audit trails. |

---

## 2. Common Interface Specification

All engines implement the standard `BaseSecurityModule` protocol defined in `backend/app/modules/interfaces.py`:

```python
class BaseSecurityModule(ABC):
    @property
    @abstractmethod
    def module_id(self) -> str: ...

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def target_phase(self) -> int: ...

    @property
    def is_operational(self) -> bool: ...

    def get_status(self) -> ModuleStatus: ...

    def initialize(self, db: Session, config: Optional[Dict[str, Any]] = None) -> None: ...

    def execute_action(self, action_name: str, payload: Dict[str, Any]) -> Dict[str, Any]: ...
```

Calling `execute_action()` on an unreleased module raises `NotImplementedError` with a clear message stating the planned release phase. This guarantees that unreleased engines cannot be accidentally invoked or presented as fake operational capabilities.

