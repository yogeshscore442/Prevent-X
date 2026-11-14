"""
PREVENT-X Attack Surface Background Tasks
"""
from backend.app.modules.attack_surface.tasks.discovery_tasks import execute_discovery_job

__all__ = ["execute_discovery_job"]
