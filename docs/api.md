# REST API Documentation — PhishGuard AI

Base URL: `http://localhost:8000` (or your deployed Render URL)

---

### 1. `GET /api/health`
Checks application health, model loaded state, and uptime.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "model_loaded": true,
  "model_name": "XGBoost Classifier",
  "model_version": "2026-10-13T16:39:29Z",
  "timestamp": 1791909727.518
}
```

---

### 2. `POST /api/predict`
Classifies a URL as legitimate or phishing using the trained machine-learning model.

**Request Body:**
```json
{
  "url": "http://paypal-security-verification.login.xyz/account/signin.php"
}
```

**Response (200 OK):**
```json
{
  "url": "http://paypal-security-verification.login.xyz/account/signin.php",
  "normalized_url": "http://paypal-security-verification.login.xyz/account/signin.php",
  "verdict": "phishing",
  "is_phishing": true,
  "risk_score": 1.0,
  "confidence": 1.0,
  "features": {
    "url_length": 65,
    "entropy_url": 4.62,
    "is_suspicious_tld": 1,
    "contains_login": 1
  },
  "indicators": [
    "Top-Level Domain (TLD) has a high historical correlation with phishing campaigns",
    "Contains sensitive authentication keyword 'login'"
  ],
  "inference_time_ms": 2.14,
  "model_version": "2026-10-13T16:39:29Z",
  "is_firewall_blocked": false,
  "firewall_rule": null
}
```

---

### 3. `GET /api/network/stats`
Returns application request counters, processing duration, and latency metrics.

**Response (200 OK):**
```json
{
  "total_requests": 42,
  "predictions_count": 18,
  "dns_lookups_count": 5,
  "blocked_requests_count": 2,
  "error_count": 0,
  "avg_latency_ms": 3.42,
  "median_latency_ms": 2.85,
  "active_firewall_rules": 2,
  "total_logged_events": 25
}
```

---

### 4. `GET /api/network/dns?domain={hostname}`
Performs bounded client-server DNS lookup without fetching the website.

**Response (200 OK):**
```json
{
  "hostname": "google.com",
  "status": "SUCCESS",
  "ipv4_addresses": ["142.250.190.46"],
  "ipv6_addresses": ["2607:f8b0:4005:805::200e"],
  "lookup_duration_ms": 14.2,
  "error": null,
  "timestamp": "2026-10-13T16:45:00Z"
}
```

---

### 5. `GET /api/firewall/rules`
Lists all simulated domain-blocking firewall rules.

---

### 6. `POST /api/firewall/rules`
Creates a simulated domain block rule.

**Request Body:**
```json
{
  "domain": "phishing-bank.top",
  "reason": "Confirmed credential harvester"
}
```

---

### 7. `DELETE /api/firewall/rules/{rule_id}`
Deletes an active firewall rule by its ID.

---

### 8. `GET /api/events`
Returns recent network and security events with pagination (`?limit=50`).
