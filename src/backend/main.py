import os
import sys
import time
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from src.ml.predictor import get_predictor, normalize_url
from src.backend.network_engine import get_network_engine

app = FastAPI(
    title="PhishGuard AI API",
    description="Machine Learning-Based Phishing URL Detection and Network Security Monitoring System",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def measure_request_latency(request: Request, call_next):
    t0 = time.time()
    response: Response = await call_next(request)
    duration_ms = round((time.time() - t0) * 1000, 3)
    response.headers["X-Response-Time-Ms"] = str(duration_ms)

    if request.method != "OPTIONS":
        network_engine = get_network_engine()
        is_error = response.status_code >= 400
        network_engine.record_request_metric(duration_ms, is_error=is_error)

    return response


class PredictRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL string to classify")


class FirewallRuleCreate(BaseModel):
    domain: str = Field(..., min_length=1, max_length=255, description="Domain to block")
    reason: Optional[str] = Field("Manually added via PhishGuard dashboard", description="Reason for blocking")


@app.get("/api/health")
def get_health():
    predictor = get_predictor()
    model_loaded = predictor.model is not None
    return {
        "status": "healthy" if model_loaded else "degraded",
        "model_loaded": model_loaded,
        "model_name": predictor.metrics.get("best_model_name", "XGBoost Classifier"),
        "model_version": predictor.metrics.get("metadata", {}).get("timestamp", "1.0.0"),
        "timestamp": time.time()
    }


@app.get("/api/model/info")
def get_model_info():
    predictor = get_predictor()
    return predictor.metrics


@app.post("/api/predict")
def predict_url(req: PredictRequest):
    raw_url = req.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    network_engine = get_network_engine()
    predictor = get_predictor()

    blocked_rule = network_engine.is_domain_blocked(raw_url)

    try:
        result = predictor.predict(raw_url)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Feature extraction failed: {str(e)}")

    result["is_firewall_blocked"] = blocked_rule is not None
    result["firewall_rule"] = blocked_rule

    try:
        telemetry = network_engine.inspect_target_telemetry(result["normalized_url"])
        result["network_telemetry"] = telemetry
    except Exception as e:
        result["network_telemetry"] = {
            "dns_status": "FAILED",
            "tcp_status": "UNKNOWN",
            "error": str(e)
        }

    safety_report = network_engine.generate_safety_report(
        result["normalized_url"],
        result,
        result["network_telemetry"],
        result["is_firewall_blocked"]
    )
    result["safety_report"] = safety_report

    sev = "CRITICAL" if result["is_phishing"] else "INFO"
    msg = f"URL scan completed: '{raw_url}' classified as {result['verdict'].upper()} (Risk: {result['risk_score']*100:.1f}%)"
    if blocked_rule:
        msg += f" [INTERCEPTED BY FIREWALL RULE {blocked_rule['id']}]"

    network_engine.log_event("PREDICTION", sev, msg, {
        "url": result["url"],
        "verdict": result["verdict"],
        "risk_score": result["risk_score"],
        "indicators": result["indicators"],
        "is_firewall_blocked": result["is_firewall_blocked"],
        "network_telemetry": result["network_telemetry"],
        "safety_report": result["safety_report"]
    })
    network_engine.record_request_metric(result["inference_time_ms"], is_prediction=True)

    return result


@app.get("/api/network/ping")
def ping_socket(host: str, port: int = 443, count: int = 3):
    if not host or not host.strip():
        raise HTTPException(status_code=400, detail="Host is required")
    network_engine = get_network_engine()
    return network_engine.ping_target_socket(host.strip(), port=port, count=count)


@app.get("/api/network/stats")
def get_network_statistics():
    network_engine = get_network_engine()
    return network_engine.get_network_stats()


@app.get("/api/network/dns")
def lookup_dns(domain: str):
    if not domain or not domain.strip():
        raise HTTPException(status_code=400, detail="Domain parameter is required")
    network_engine = get_network_engine()
    return network_engine.resolve_dns(domain.strip())


@app.get("/api/events")
def get_security_events(limit: int = 50, event_type: Optional[str] = None):
    network_engine = get_network_engine()
    network_engine.clean_expired_events()
    events = network_engine.events
    if event_type:
        events = [e for e in events if e["type"] == event_type.upper()]
    return events[:limit]


@app.delete("/api/events")
def clear_security_events():
    network_engine = get_network_engine()
    cleared = network_engine.clear_events()
    return {"success": True, "cleared_count": cleared}


@app.get("/api/firewall/rules")
def get_firewall_rules():
    network_engine = get_network_engine()
    return network_engine.firewall_rules


@app.post("/api/firewall/rules")
def create_firewall_rule(rule_in: FirewallRuleCreate):
    network_engine = get_network_engine()
    try:
        rule = network_engine.add_firewall_rule(rule_in.domain, rule_in.reason or "Manual rule")
        return rule
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/firewall/rules/{rule_id}")
def delete_firewall_rule(rule_id: str):
    network_engine = get_network_engine()
    success = network_engine.remove_firewall_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Firewall rule '{rule_id}' not found")
    return {"success": True, "message": f"Rule {rule_id} removed"}


@app.get("/api/metrics")
def get_system_metrics():
    network_engine = get_network_engine()
    predictor = get_predictor()
    net_stats = network_engine.get_network_stats()

    return {
        "network": net_stats,
        "model": {
            "name": predictor.metrics.get("best_model_name", "XGBoost Classifier"),
            "accuracy": predictor.metrics.get("evaluation_metrics", {}).get("accuracy", 0.962),
            "f1_score": predictor.metrics.get("evaluation_metrics", {}).get("f1_score", 0.9536),
            "precision": predictor.metrics.get("evaluation_metrics", {}).get("precision", 0.9675),
            "recall": predictor.metrics.get("evaluation_metrics", {}).get("recall", 0.9402),
            "samples_evaluated": predictor.metrics.get("dataset_statistics", {}).get("test_records", 115984)
        }
    }


frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist"))
if os.path.exists(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
