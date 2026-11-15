"""
PREVENT-X Payload Normalization REST API
Provides endpoints for inspecting and canonicalizing payloads with evasion detection.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.organization import Organization
from backend.app.modules.network_defense.normalization.normalizer import (
    payload_normalizer,
)
from backend.app.schemas.network_defense import (
    PayloadNormalizationRequest,
    PayloadNormalizationResponse,
)
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    require_permission,
)

router = APIRouter(prefix="/network-defense/normalization", tags=["Advanced Network Defense - Normalization"])


@router.post(
    "/inspect",
    response_model=PayloadNormalizationResponse,
    dependencies=[Depends(require_permission(PermissionCode.VIRTUAL_PATCH_READ))],
)
def inspect_and_normalize_payload(
    payload: PayloadNormalizationRequest,
    org: Organization = Depends(get_current_organization),
):
    """
    Normalizes an input payload through URL, HTML, Unicode, Hex, and JSON decoding passes.
    Identifies obfuscation evasion techniques without altering the raw evidence.
    """
    norm = payload_normalizer.normalize(payload.payload)
    return PayloadNormalizationResponse(
        raw_text=norm.raw_text,
        normalized_text=norm.normalized_text,
        obfuscation_detected=norm.obfuscation_detected,
        detected_techniques=norm.detected_techniques,
        extracted_base64_fragments=norm.extracted_base64_fragments,
    )
