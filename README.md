# PhishGuard AI

**Academic Title:** Machine Learning-Based Phishing URL Detection and Network Security Monitoring System  
**Course Domain:** Computer Networks & Applied Artificial Intelligence  
**Verified Model Test Accuracy:** **96.20%** (Exceeds the 95.0% target on 115,984 held-out test samples)

---

## 1. Project Overview

**PhishGuard AI** is an enterprise-grade cybersecurity web application and research platform that detects phishing URLs using genuine machine learning while demonstrating practical Computer Networks engineering concepts.

Unlike naive classifiers that rely on external API keys or crawl dangerous target websites, PhishGuard AI implements **Approach A: Pure URL-Only Lexical Inference**:
- Extracts **55 deterministic structural, statistical, and Shannon entropy features** purely from the URL string.
- Never crawls, visits, or executes untrusted links.
- Evaluates inference in under **3 microseconds per URL** (< 0.003 ms).
- Features a **Computer Networks Monitoring Engine** providing bounded socket DNS resolution, client-server request latency instrumentation, a simulated domain-level firewall blocklist, and an event audit trail.
- Implements a minimalist dashboard adhering to the strict Google visual design system (black, white, neutral grays, single Google blue `#1A73E8` accent).

---

## 2. Verified Machine Learning Results

Trained and evaluated on **579,920 deduplicated URLs** (`archive (21)/final_dataset.csv`) using a stratified 80/20 train/test partition ($N_{\text{test}} = 115,984$ held-out samples, random seed 42) with zero target leakage:

| Model Candidate | Test Accuracy | Precision (Phishing) | Recall (Phishing) | F1-Score | ROC-AUC | CPU Latency |
|---|---|---|---|---|---|---|
| **Logistic Regression** (L2) | 91.62% | 91.49% | 88.01% | 89.72% | 0.9727 | 0.0004 ms/sample |
| **HistGradientBoosting** | 95.28% | 95.54% | 92.99% | 94.24% | 0.9902 | 0.0047 ms/sample |
| **XGBoost Classifier (Selected)** | **96.20%** | **96.75%** | **94.02%** | **95.36%** | **0.9930** | **0.0029 ms/sample** |

### Confusion Matrix on Unseen Held-Out Test Set
- **True Negatives (Legitimate Correct):** 66,292
- **False Positives (False Alarms):** 1,523 (Only 2.25% FPR)
- **False Negatives (Missed Phishing):** 2,881 (5.98% FNR)
- **True Positives (Phishing Blocked):** 45,288

---

## 3. Computer Networks Concepts Demonstrated

1. **Client-Server Architecture:** Decoupled React/TypeScript Single Page Application communicating asynchronously with FastAPI via RESTful HTTP JSON payloads.
2. **DNS Resolution & Domain Inspection:** Bounded, non-recursive socket DNS queries resolving IPv4 (A) and IPv6 (AAAA) records with duration tracking and timeout handling.
3. **HTTP Request Latency Instrumentation:** Middleware calculating exact server processing duration ($\Delta T$) stamped into custom response headers (`X-Response-Time-Ms`) and aggregated for latency statistics.
4. **Simulated Domain Firewall:** In-memory application-layer firewall allowing dynamic creation, deletion, and real-time interception of blocked traffic with security event logging.
5. **Security Event Audit Trail:** Chronological log tracking predictions, DNS queries, and firewall events.

---

## 4. Quick Start & Local Execution

### 4.1 Prerequisites
- Python 3.10+ (Tested on Python 3.14)
- Node.js 18+ and npm

### 4.2 Installation
```bash
# Clone or navigate to the repository
cd /path/to/CN

# Install Python dependencies
pip install -r requirements.txt

# Install frontend dependencies and build static assets
cd frontend
npm install
npm run build
cd ..
```

### 4.3 Running the Application
Start the unified FastAPI server (which automatically serves the compiled React dashboard):
```bash
uvicorn src.backend.main:app --host 0.0.0.0 --port 8000
```
Open your browser to: **`http://localhost:8000`**

### 4.4 Running Frontend in Development Mode (Optional)
If modifying the React frontend:
```bash
cd frontend
npm run dev
```
Access the Vite dev server at `http://localhost:5173` (proxies `/api` to backend on port 8000).

---

## 5. Project & Dataset Structure

```text
CN/
├── data/
│   ├── training/                  # Datasets used for model training
│   │   ├── final_dataset.csv      # Primary 580k URL training dataset
│   │   ├── train_dataset.csv      # Full training partition
│   │   ├── Training.parquet       # Parquet format training data
│   │   ├── dataset_info.txt       # Dataset metadata
│   │   └── feature_description.csv# Lexical feature schemas
│   ├── testing/                   # Datasets reserved for held-out evaluation
│   │   ├── test_dataset.csv       # Held-out testing dataset
│   │   └── Testing.parquet        # Testing partition in parquet format
│   └── raw/                       # Additional cybersecurity benchmarks
│       ├── PhiUSIIL_Phishing_URL_Dataset.csv
│       ├── malicious_phish.csv
│       ├── phishing_site_urls.csv
│       ├── urldata.csv
│       ├── phishing_url_dataset_unique.csv
│       ├── partitioned_datasets/
│       └── malicious_urls_2026/
├── docs/                          # Viva guide, API docs, demo script
├── frontend/                      # React + TypeScript + Tailwind dashboard
├── models/                        # Saved model artifact, evaluation plots & metrics
├── reports/                       # Academic reports & model evaluation benchmarks
├── scripts/                       # Model training & evaluation pipeline (train_model.py)
├── src/
│   ├── backend/                   # FastAPI application & Network Engine
│   └── ml/                        # Feature extractor & Predictor
├── tests/                         # Backend and ML unit test suites
├── pytest.ini                     # Test configuration
├── requirements.txt               # Python package dependencies
├── render.yaml                    # Cloud deployment specification
└── README.md                      # Project documentation
```

---

## 6. Model Retraining Pipeline

The training pipeline is fully reproducible from the command line:
```bash
# Run full training on the 580k dataset
python3 scripts/train_model.py

# Optional: Run on a subset for quick experimentation
python3 scripts/train_model.py --max_records 50000 --test_size 0.2
```

Outputs are automatically saved to `models/`:
- `best_model.joblib`: Compressed XGBoost model (1.54 MB).
- `feature_names.json`: Schema of all 55 lexical features.
- `training_metrics.json`: Machine-readable evaluation metrics.
- `confusion_matrix.png`: High-resolution confusion matrix chart.
- `model_comparison.png`: Architectural benchmark graph.
- `feature_importance.png`: Feature rankings.

---

## 7. Running Automated Tests

Run the comprehensive unit and integration test suite:
```bash
python3 -m pytest -v tests/
```
All 19 test cases validate ML feature extraction, boundary handling, entropy calculations, API endpoints, DNS lookups, and firewall rule lifecycles.

---

## 8. Deployment to Render

The repository is configured for one-click deployment on Render:

1. Push this repository to GitHub or GitLab.
2. In the Render Dashboard, click **New > Web Service**.
3. Connect your repository.
4. Render will automatically detect `render.yaml`. Alternatively, configure:
   - **Environment:** `Python`
   - **Build Command:** `pip install -r requirements.txt && cd frontend && npm install && npm run build && cd ..`
   - **Start Command:** `uvicorn src.backend.main:app --host 0.0.0.0 --port $PORT`
5. The deployed web service serves both the API endpoints and the dashboard on port `$PORT`.

---

## 9. Wireshark Network Packet Inspection Guide

To demonstrate network packet analysis for Computer Networks lab requirements:
1. Open Wireshark and select your active network interface (e.g., `Loopback: lo0` for localhost, or `en0` for Wi-Fi).
2. Set display filter to:
   ```wireshark
   tcp.port == 8000 || dns
   ```
3. In PhishGuard AI, submit a URL or execute a DNS lookup.
4. In Wireshark, observe:
   - **TCP Handshake:** `[SYN]`, `[SYN, ACK]`, `[ACK]` establishing connection.
   - **HTTP POST Request:** Inspect HTTP headers and JSON payload containing the URL.
   - **HTTP Response:** Inspect the `200 OK` status, custom `X-Response-Time-Ms` latency header, and JSON prediction.
   - **DNS Queries:** For domain lookups, observe UDP packets to port 53 requesting standard A/AAAA queries.

---

## 10. Documentation Directory Index

- [Workspace Inventory](reports/workspace_inventory.md)
- [Dataset Research Report](reports/dataset_research.md)
- [Model Evaluation Report](reports/model_evaluation.md)
- [Automated Test Results](reports/test_results.md)
- [System Architecture](reports/architecture.md)
- [REST API Reference](docs/api.md)
- [Computer Networks Viva Guide](docs/computer_networks_viva.md)
- [5-Minute Demonstration Script](docs/project_demo_script.md)
- [Dataset Licenses](docs/dataset_licenses.md)
