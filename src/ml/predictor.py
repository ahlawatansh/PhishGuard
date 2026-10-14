import os
import json
import time
from urllib.parse import urlparse
import joblib
import numpy as np
from typing import Dict, Any, List

from src.ml.feature_extractor import extract_features, extract_features_vector, FEATURE_NAMES

DEFAULT_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "models", "best_model.joblib")
DEFAULT_METRICS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "models", "training_metrics.json")


def normalize_url(url: str) -> str:
    u = str(url).strip()
    if not u:
        return ""
    if not u.startswith(('http://', 'https://', 'ftp://')):
        u = 'https://' + u
    try:
        parsed = urlparse(u)
        if not parsed.path:
            u = u + '/'
    except Exception:
        pass
    return u


class PhishGuardPredictor:
    def __init__(self, model_path: str = DEFAULT_MODEL_PATH, metrics_path: str = DEFAULT_METRICS_PATH):
        self.model_path = os.path.abspath(model_path)
        self.metrics_path = os.path.abspath(metrics_path)
        self.model = None
        self.metrics = None
        self.load_model()

    def load_model(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model artifact not found at {self.model_path}")
        self.model = joblib.load(self.model_path)

        if os.path.exists(self.metrics_path):
            with open(self.metrics_path, "r") as f:
                self.metrics = json.load(f)
        else:
            self.metrics = {}

    def predict(self, url: str) -> Dict[str, Any]:
        t0 = time.time()
        raw_url = str(url).strip()
        if not raw_url:
            raise ValueError("URL cannot be empty")

        normalized = normalize_url(raw_url)

        features_dict = extract_features(normalized)
        vector = [features_dict[fn] for fn in FEATURE_NAMES]
        X = np.array([vector], dtype=np.float32)

        pred_label = int(self.model.predict(X)[0])
        prob_score = float(self.model.predict_proba(X)[0][1]) if hasattr(self.model, "predict_proba") else (1.0 if pred_label == 1 else 0.0)

        inference_time_ms = (time.time() - t0) * 1000

        indicators = []
        if features_dict.get('is_ip_address', 0) == 1:
            indicators.append("Host is an IP address rather than a domain name")
        if features_dict.get('is_suspicious_tld', 0) == 1:
            indicators.append("Top-Level Domain (TLD) has a high historical correlation with phishing campaigns")
        if features_dict.get('entropy_url', 0) > 4.5:
            indicators.append(f"High information entropy ({features_dict['entropy_url']:.2f} bits/char) suggesting randomized/obfuscated characters")
        if features_dict.get('contains_login', 0) == 1:
            indicators.append("Contains sensitive authentication keyword 'login'")
        if features_dict.get('contains_verify', 0) == 1:
            indicators.append("Contains credential verification keyword 'verify'")
        if features_dict.get('contains_bank', 0) == 1:
            indicators.append("Contains financial banking keyword 'bank'")
        if features_dict.get('unusual_double_slash', 0) == 1:
            indicators.append("Contains abnormal '//' redirection path sequence")
        if features_dict.get('multiple_http', 0) == 1:
            indicators.append("Contains multiple embedded HTTP/HTTPS schemes")
        if features_dict.get('url_depth', 0) > 4:
            indicators.append(f"Excessive path directory depth ({features_dict['url_depth']} levels)")
        if features_dict.get('num_percent', 0) > 2:
            indicators.append(f"Multiple percent-encoded obfuscation sequences ({features_dict['num_percent']})")

        verdict = "phishing" if pred_label == 1 else "legitimate"
        confidence = prob_score if pred_label == 1 else (1.0 - prob_score)

        return {
            "url": raw_url,
            "normalized_url": normalized,
            "verdict": verdict,
            "is_phishing": bool(pred_label == 1),
            "risk_score": round(prob_score, 4),
            "confidence": round(confidence, 4),
            "features": features_dict,
            "indicators": indicators,
            "inference_time_ms": round(inference_time_ms, 3),
            "model_version": self.metrics.get("metadata", {}).get("timestamp", "1.0.0")
        }


_predictor_instance = None


def get_predictor() -> PhishGuardPredictor:
    global _predictor_instance
    if _predictor_instance is None:
        _predictor_instance = PhishGuardPredictor()
    return _predictor_instance
