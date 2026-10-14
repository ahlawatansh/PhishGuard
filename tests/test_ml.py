import pytest
import os
import numpy as np

from src.ml.feature_extractor import extract_features, extract_features_vector, FEATURE_NAMES, shannon_entropy
from src.ml.predictor import get_predictor, normalize_url


def test_feature_names_count():
    assert len(FEATURE_NAMES) == 55


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert abs(shannon_entropy("ab") - 1.0) < 1e-4


def test_extract_features_schema_integrity():
    url = "https://www.example.com/test?param=1"
    feats = extract_features(url)
    assert len(feats) == 55
    for fn in FEATURE_NAMES:
        assert fn in feats
        assert isinstance(feats[fn], (int, float))


def test_url_normalization():
    assert normalize_url("google.com") == "https://google.com/"
    assert normalize_url("http://test.com/abc") == "http://test.com/abc"
    assert normalize_url("") == ""


def test_malformed_and_extreme_urls():
    extreme_cases = [
        "https://" + "a" * 2000 + ".com",
        "http://127.0.0.1:8080/test///weird//path",
        "https://user:pass@evil-domain.top:443/login?q=%20%25",
        "ftp://host.name/path?a=1&b=2&c=3#fragment"
    ]
    for u in extreme_cases:
        feats = extract_features(u)
        assert len(feats) == 55
        vec = extract_features_vector(u)
        assert len(vec) == 55
        for v in vec:
            assert not np.isnan(v)
            assert not np.isinf(v)


def test_predictor_model_loaded():
    predictor = get_predictor()
    assert predictor.model is not None
    assert predictor.metrics is not None


def test_prediction_output_contract():
    predictor = get_predictor()
    res = predictor.predict("https://www.google.com")

    assert "url" in res
    assert "normalized_url" in res
    assert "verdict" in res
    assert res["verdict"] in ["legitimate", "phishing"]
    assert "is_phishing" in res
    assert isinstance(res["is_phishing"], bool)
    assert "risk_score" in res
    assert 0.0 <= res["risk_score"] <= 1.0
    assert "confidence" in res
    assert 0.5 <= res["confidence"] <= 1.0
    assert "inference_time_ms" in res
    assert res["inference_time_ms"] > 0
    assert "features" in res
    assert len(res["features"]) == 55


def test_phishing_url_detection():
    predictor = get_predictor()
    known_phish = "http://paypal-verification-update.security-login.xyz/signin.php?token=9238472"
    res = predictor.predict(known_phish)
    assert res["verdict"] == "phishing"
    assert res["risk_score"] > 0.8
    assert len(res["indicators"]) > 0


def test_legitimate_url_detection():
    predictor = get_predictor()
    known_legit = "https://en.wikipedia.org/wiki/Computer_network"
    res = predictor.predict(known_legit)
    assert res["verdict"] == "legitimate"
    assert res["risk_score"] < 0.5


def test_institutional_cctld_detection():
    predictor = get_predictor()
    res = predictor.predict("https://vtop.vit.ac.in/")
    assert res["verdict"] == "legitimate"
    assert res["risk_score"] < 0.35
