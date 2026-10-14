<div align="center">

# PhishGuard AI — Real-Time Phishing URL Detection & Network Defense

**A machine learning cybersecurity system with pure URL lexical analysis, real-time TCP socket telemetry, DNS diagnostics, and an application-layer firewall.**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61dafb.svg?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-blue.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-v3.4-38bdf8.svg?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![XGBoost](https://img.shields.io/badge/XGBoost-96.2%25%20Acc-FF6F00.svg)](https://xgboost.ai/)
[![Vite](https://img.shields.io/badge/Vite-5.4-646cff.svg?logo=vite&logoColor=white)](https://vitejs.dev/)

### 🔗 Live: [phishguard-ai.onrender.com](https://phishguard-ai.onrender.com/)

</div>

---

## What it is

I built PhishGuard AI because most phishing detectors either blindly query black-box external APIs, or crawl live destination web pages to parse HTML tags—a dangerous approach that exposes corporate networks to malicious drive-by downloads. 

PhishGuard AI takes a deterministic approach: it extracts 55 structural, statistical, and Shannon entropy features directly from the raw URL string, evaluating threats in under 3 microseconds without ever visiting or rendering the target site. Coupled with a machine learning engine trained on over 579,000 verified URLs (achieving 96.20% accuracy), it pairs AI classification with real Computer Networks fundamentals—safe DNS lookups, live Layer 4 TCP 3-way handshake latency measurements, TLS certificate validation, and an in-memory application firewall that intercepts suspicious outbound requests.

---

## Features

**Deterministic Lexical ML** — extracts 55 zero-network features (length, directory depth, Shannon entropy, obfuscated hex/base64 sequences, TLD risk, sensitive credential keywords) purely from the URL string. Inference takes < 0.003 ms per sample.

**Live Network Telemetry** — inspects Layer 7 DNS (A and AAAA records), Layer 4 TCP SYN-ACK handshake round-trip time, and Layer 6 TLS 1.3 cryptographic handshakes in real time without executing untrusted web payloads.

**Socket Latency & Jitter Probes** — sends back-to-back TCP socket probes to target hosts to calculate average RTT, jitter, and packet loss metrics directly from the browser dashboard.

**Application-Layer Firewall** — an in-memory domain blocklist engine that intercepts URL prediction requests, prevents routing to confirmed phishing hosts, and tracks rule hits dynamically.

**Security Event Logging** — real-time chronological audit trail capturing predictions, DNS resolutions, latency changes, and firewall interceptions with severity ratings (INFO, WARNING, CRITICAL).

**Minimalist Dashboard** — responsive single-page dashboard built with React 18, TypeScript, and Tailwind, featuring a dedicated scanner, live network diagnostics, firewall rule management, model benchmark comparisons, and security event logs.

---

## Stack

| Layer | Tech |
|---|---|
| Frontend | React 18, TypeScript, Tailwind CSS, Lucide Icons, Motion |
| Backend | Python 3.11+, FastAPI, Uvicorn, Pydantic |
| Machine Learning | XGBoost, Scikit-Learn, NumPy, Pandas, Joblib |
| Network Telemetry | Python Sockets (`socket`, `ssl`), DNS resolution, TCP handshake tracking |
| Build & Tests | Vite 5, Pytest, Pytest-Asyncio |

---

## Project structure

```text
CN/
├── data/
│   ├── training/                  # 580k URL training dataset & metadata
│   ├── testing/                   # Held-out evaluation partitions
│   └── raw/                       # Additional raw benchmark datasets
├── frontend/                      # React 18 dashboard
│   ├── dist/                      # Production compiled assets
│   ├── src/                       # Components, scanner, telemetry UI & API client
│   ├── index.html
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.ts
├── models/                        # Saved model artifacts & benchmark charts
│   ├── best_model.joblib          # Trained XGBoost model artifact (96.20% test accuracy)
│   ├── feature_names.json         # 55 deterministic lexical feature schemas
│   ├── training_metrics.json      # Machine-readable test metrics
│   ├── confusion_matrix.png       # Test set confusion matrix
│   ├── feature_importance.png     # Top lexical feature rankings
│   └── model_comparison.png       # Candidate benchmark bar charts
├── scripts/
│   └── train_model.py             # Reproducible training & evaluation pipeline
├── src/
│   ├── backend/
│   │   ├── main.py                # FastAPI application & REST route definitions
│   │   └── network_engine.py      # Socket telemetry, DNS resolver & simulated firewall
│   └── ml/
│       ├── feature_extractor.py   # Pure-Python 55 deterministic feature extractor
│       └── predictor.py           # Model inference engine & risk scoring
├── tests/
│   ├── test_backend.py            # API endpoint & firewall lifecycle test suite
│   └── test_ml.py                 # Feature extractor & predictor test suite
├── pytest.ini                     # Direct pytest configuration
├── render.yaml                    # Cloud deployment specification
├── requirements.txt               # Backend Python dependencies
└── README.md
```

---

## API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check, model status, and service uptime |
| `GET` | `/api/model/info` | Trained model architecture, accuracy, and feature schema |
| `POST` | `/api/predict` | Classify URL, extract 55 features, and inspect firewall rules |
| `GET` | `/api/network/dns` | Non-recursive bounded DNS resolution for domain (A / AAAA) |
| `GET` | `/api/network/ping` | Layer 4 TCP socket latency and jitter probe |
| `GET` | `/api/network/stats` | Aggregated latency, request volume, and network metrics |
| `GET` | `/api/events` | Retrieve chronological security event audit trail |
| `GET` | `/api/firewall/rules` | List simulated domain-blocking firewall rules |
| `POST` | `/api/firewall/rules` | Add a new domain block rule |
| `DELETE` | `/api/firewall/rules/{id}` | Delete a simulated firewall rule |
| `GET` | `/api/metrics` | System-wide combined network and ML performance summary |

---

<div align="center">
<sub>Built by <a href="https://github.com/ahlawatansh">Ansh Ahlawat</a> · CSE undergrad, VIT Vellore</sub>
</div>
