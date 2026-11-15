"""
Tests for PREVENT-X ML Traffic Classification Engine (Phase 10)
Validates feature extraction, Random Forest ensemble holdout metrics (Precision, Recall, F1),
explainable feature attribution, advisory-only policy, and REST API endpoints.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.modules.network_defense.ml.classifier import (
    MODEL_VERSION,
    RandomForestClassifier,
    classifier_model,
)
from backend.app.modules.network_defense.ml.dataset import DOCUMENTED_BENCHMARK_DATASET
from backend.app.modules.network_defense.ml.feature_extractor import (
    FEATURE_NAMES,
    feature_extractor,
)
from backend.app.modules.network_defense.ml.service import ml_classification_service


def test_feature_extraction_accuracy():
    """Verifies that 16 distinct numerical features are properly extracted."""
    feats = feature_extractor.extract_features(
        method="POST",
        path="/api/v1/search",
        query="q=test&limit=10",
        body='{"query": "UNION SELECT 1,2,3--"}',
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
    )

    assert len(feats) == 16
    assert feats[0] >= 1.0  # threat_signal_count (UNION SELECT)
    assert feats[1] >= 1.0  # sqli_keyword_count
    assert feats[6] > 0.0  # shannon_entropy
    assert feats[10] > 0.0  # url_length
    assert feats[11] >= 3.0  # path_depth (/api/v1/search)
    assert feats[15] == 1.0  # content_type_is_json


def test_model_training_and_holdout_metrics():
    """Verifies genuine holdout train/test evaluation with documented precision, recall, and F1."""
    clf = RandomForestClassifier(n_estimators=20, max_depth=5)
    clf.fit_and_evaluate(DOCUMENTED_BENCHMARK_DATASET, test_ratio=0.3)

    assert clf.is_trained is True
    metrics = clf.metrics
    assert metrics["train_samples"] > 0
    assert metrics["test_samples"] > 0
    assert metrics["precision"] >= 0.70
    assert metrics["recall"] >= 0.70
    assert metrics["f1"] >= 0.70


def test_classification_inference_and_explainability():
    """Verifies benign vs malicious classification and explainable feature importances."""
    # 1. Benign request
    benign_res = ml_classification_service.classify_request(
        method="GET",
        path="/api/v1/products",
        query_string="category=electronics&page=1&limit=25",
        body="",
    )
    assert benign_res.is_anomalous is False
    assert benign_res.anomaly_score < 0.5
    assert benign_res.predicted_class == "BENIGN"
    assert benign_res.is_advisory_only is True

    # 2. Malicious exploit request
    malicious_res = ml_classification_service.classify_request(
        method="POST",
        path="/api/v1/search",
        query_string="q=1' UNION SELECT 1,username,password FROM users--",
        body='{"input": "1; DROP TABLE customers;--"}',
    )
    assert malicious_res.is_anomalous is True
    assert malicious_res.anomaly_score >= 0.5
    assert malicious_res.predicted_class == "ANOMALOUS_ATTACK"
    assert malicious_res.is_advisory_only is True

    # Verify explainability: top features must be populated
    assert len(malicious_res.top_feature_importances) > 0


def test_ml_api_endpoints(client: TestClient, test_tenants):
    """Tests the ML classification REST API endpoints."""
    admin_a = test_tenants["admin_a"]

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": admin_a.email, "password": "AlphaAdminPass123!"},
    )
    assert login_res.status_code == 200
    token_a = login_res.json()["tokens"]["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 1. Status endpoint
    status_res = client.get("/api/v1/network-defense/ml/status", headers=headers_a)
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["model_version"] == MODEL_VERSION
    assert status_data["is_ready"] is True
    assert status_data["advisory_mode"] is True
    assert status_data["f1_score"] > 0.5

    # 2. Classify endpoint
    classify_res = client.post(
        "/api/v1/network-defense/ml/classify",
        json={
            "method": "POST",
            "path": "/api/v1/feedback",
            "query_string": "",
            "body": '{"comment": "Excellent service and fast support!"}',
        },
        headers=headers_a,
    )
    assert classify_res.status_code == 200
    class_data = classify_res.json()
    assert class_data["predicted_class"] == "BENIGN"
    assert class_data["is_advisory_only"] is True
