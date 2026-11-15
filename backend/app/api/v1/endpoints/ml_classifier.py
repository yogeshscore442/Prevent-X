"""
PREVENT-X ML Traffic Classification REST API
Provides endpoints for evaluating requests against the Random Forest ensemble,
inspecting explainable feature attributions, and querying model telemetry metrics.
"""

import logging

from fastapi import APIRouter, Depends

from backend.app.models.organization import Organization
from backend.app.modules.network_defense.ml.service import (
    ml_classification_service,
)
from backend.app.schemas.network_defense import (
    MLClassificationRequest,
    MLClassificationResponse,
    MLModelStatusResponse,
)
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    require_permission,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/network-defense/ml",
    tags=["Advanced Network Defense - ML Traffic Classification"],
)


@router.post(
    "/classify",
    response_model=MLClassificationResponse,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def classify_traffic_request(
    req: MLClassificationRequest,
    org: Organization = Depends(get_current_organization),
):
    """
    Evaluates an HTTP request through the 16-feature Random Forest ensemble.
    Returns explainable feature contributions and an advisory anomaly score.
    """
    return ml_classification_service.classify_request(
        method=req.method,
        path=req.path,
        query_string=req.query_string,
        body=req.body,
        headers=req.headers,
    )


@router.get(
    "/status",
    response_model=MLModelStatusResponse,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def get_ml_model_status(
    org: Organization = Depends(get_current_organization),
):
    """
    Returns model versioning, feature dimension count, holdout evaluation metrics
    (Precision, Recall, F1), and confirms advisory-only operation.
    """
    return ml_classification_service.get_model_status()
