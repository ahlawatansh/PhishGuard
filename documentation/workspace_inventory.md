# Workspace Inventory Report — PhishGuard AI

**Date:** 2026-10-13  
**Project:** PhishGuard AI (Machine Learning-Based Phishing URL Detection and Network Security Monitoring System)  
**Workspace Path:** `/Users/ansh/Desktop/CN`

---

## 1. Executive Summary

An exhaustive inspection of `/Users/ansh/Desktop/CN` was conducted. The workspace contains an exceptional collection of high-quality cybersecurity and phishing URL datasets (over 2.5 million URLs across 13 root CSV files and 7 extracted archive folders, totaling >2 GB of data). Prior to this implementation, no backend framework, frontend dashboard, or training scripts existed. The workspace was an uninitialized project folder with datasets downloaded and ready for engineering.

---

## 2. System and Runtime Environment

- **Operating System:** macOS (Darwin arm64)
- **Available Disk Space:** 31 GB available on `/System/Volumes/Data` (out of 228 GB, 85% used)
- **Python Version:** Python 3.14.5 (`/Library/Frameworks/Python.framework/Versions/3.14/bin/python3`)
- **Node.js Version:** v26.8.2
- **npm Version:** 11.19.1
- **Installed Core Python Libraries:**
  - `pandas` (Available)
  - `numpy` (Available)
  - `scikit-learn` (Available)
  - `xgboost` (Available)
  - `fastapi` (Available)
  - `uvicorn` (Available)
  - `joblib` (Available)
  - `matplotlib` (Available)
  - `requests` (Available)
  - `pydantic` (Available)

---

## 3. Discovered Local Datasets Inventory

| File / Folder | File Size | Record Count | Schema / Features | Target Column & Classes | Assessment |
|---|---|---|---|---|---|
| `archive (21)/final_dataset.csv` | ~38 MB | 579,920 | 76 cols (55 lexical features, 9 DNS, 12 WHOIS) + raw `url` | `label`: 0=Legitimate (339,074, 58.5%), 1=Phishing (240,846, 41.5%) | **Gold Standard Candidate.** Huge sample size, verified ground truth, 55 clean lexical features calculable purely from URL strings with zero webpage fetching. |
| `PhiUSIIL_Phishing_URL_Dataset.csv` | 54.22 MB | 235,795 | 56 cols (URL, lexical, web-structure features) | `label`: 0=Phishing (100,945), 1=Legitimate (134,850) | Official UCI PhiUSIIL dataset. Note inverted label encoding (1=legitimate, 0=phishing). Many features depend on webpage scraping (external refs, tags). |
| `malicious_phish.csv` | 43.55 MB | 651,191 | 2 cols (`url`, `type`) | `type`: benign (428,103), defacement (96,457), phishing (94,111), malware (32,520) | Multi-class URL dataset. Highly diverse lexical dataset. |
| `phishing_site_urls.csv` | 30.10 MB | 549,346 | 2 cols (`URL`, `Label`) | `Label`: good (392,924), bad (156,422) | Large binary raw URL dataset. |
| `urldata.csv` | 33.78 MB | 450,176 | 4 cols (`url`, `label`, `result`) | `label`: benign (345,738), malicious (104,438) | Clean raw URL dataset. |
| `phishing_url_dataset_unique.csv` | 1.80 MB | 48,812 | 3 cols (`url`, `label`, `source`) | `label`: 0=tranco benign (24,406), 1=urlhaus/openphish (24,406) | Balanced Tranco + URLhaus/OpenPhish benchmark. |
| `archive (15)/train_dataset.csv` | ~660 MB | ~1.5M | 60 cols (lexical + Hamming + sensitive words) | `label`: binary | Extremely detailed lexical feature extraction. |
| `archive (19)/` | ~170 MB | Multiple CSVs | Features + URLs | Multi-class / binary | Recent 2026 malicious URL benchmark. |

---

## 4. Existing Model Artifacts & Code

- **Existing Models:** None.
- **Existing Preprocessing / Training Code:** None.
- **Existing Backend / Frontend:** None.
- All components will be implemented cleanly from scratch using modern best practices.

---

## 5. Potential Compatibility & Engineering Considerations

1. **Approach A vs Approach B:**
   - As mandated by the Master Prompt, **Approach A (URL-Only Lexical Model)** is strictly preferred for deployment. Real-time inference should never fetch, crawl, or render hostile destination websites.
   - Network DNS lookups must be performed safely as an independent diagnostic tool rather than a dependency for AI classification.
2. **Feature Leakage Prevention:**
   - In `archive (21)`, WHOIS and live DNS features (`dns_resolves`, `domain_age_days`, `whois_missing`) could cause data leakage or fail during offline inference. Therefore, only deterministic, reproducible URL lexical features will be used in the core ML pipeline.
3. **Resource Management:**
   - Model must be lightweight and fast to execute on standard CPU architectures (Render free-tier constraints, <512MB RAM). Models like HistGradientBoosting / XGBoost / Random Forest or calibrated Linear ensembles trained on numerical lexical features + n-grams provide ultra-fast (<2ms) deterministic inference without GPU overhead.

---

## 6. Implementation Roadmap

1. **Phase 1 & 2:** Dataset research documentation and formal ML problem definition (`reports/dataset_research.md`).
2. **Phase 3:** Deterministic lexical feature extractor (`src/ml/feature_extractor.py`), reusable training script (`scripts/train_model.py`), hyperparameter tuning, model evaluation (>95% accuracy target), and artifact persistence in `models/`.
3. **Phase 4 & 5:** FastAPI backend (`src/backend/main.py`) with DNS diagnostics, network latency tracking, simulated firewall engine, and event history.
4. **Phase 6:** React + TypeScript + Vite dashboard with strict Google minimalist visual design system (black, white, neutral grays, single Google blue `#1A73E8` accent).
5. **Phase 7:** Automated ML, backend, frontend, and integration test suites (`reports/test_results.md`).
6. **Phase 8:** Render deployment configuration (`render.yaml`, environment templates, production build scripts).
7. **Phase 9:** Comprehensive academic documentation, Computer Networks Viva guide, and demo scripts.
