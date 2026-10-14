# Model Evaluation & Verification Report — PhishGuard AI

**Date:** 2026-10-13  
**Project:** PhishGuard AI  
**Author:** AI/ML Cybersecurity Engineering Team  

---

## 1. Executive Summary

A reproducible machine-learning training pipeline was built and executed on the complete, verified 579,920-sample dataset (`archive (21)/final_dataset.csv`). Three diverse candidate model families were trained and evaluated using an honest, stratified held-out test split (20% = 115,984 samples) with random seed 42:

1. **Logistic Regression (Standardized baseline)**
2. **HistGradientBoostingClassifier (LightGBM-inspired histogram boosting)**
3. **XGBoost Classifier (Extreme Gradient Boosting with histogram tree method)**

All models operated strictly on **55 deterministic URL lexical features** with zero target leakage, zero post-outcome dependencies, and zero unsafe webpage fetching.

The **XGBoost Classifier** emerged as the superior model across all primary evaluation metrics:
- **Test Accuracy:** **96.20%** (Exceeds the 95.0% target)
- **Test Precision (Phishing Detection):** **96.75%**
- **Test Recall (Phishing Detection):** **94.02%**
- **Test F1-Score (Phishing Detection):** **95.36%**
- **ROC-AUC Score:** **0.9930**
- **Inference Latency:** **0.0029 ms / sample** (< 3 microseconds on CPU)
- **Model Artifact Size:** **1.54 MB** (Optimized for Render free-tier deployment)

---

## 2. Quantitative Model Comparison

| Model Architecture | Test Accuracy | Phishing Precision | Phishing Recall | Phishing F1-Score | ROC-AUC | Training Time | CPU Inference Latency |
|---|---|---|---|---|---|---|---|
| **Logistic Regression** (L2 penalty) | 91.62% | 91.49% | 88.01% | 89.72% | 0.9727 | 2.96s | 0.0004 ms/sample |
| **HistGradientBoosting** | 95.28% | 95.54% | 92.99% | 94.24% | 0.9902 | 18.48s | 0.0047 ms/sample |
| **XGBoost Classifier** (Selected) | **96.20%** | **96.75%** | **94.02%** | **95.36%** | **0.9930** | 8.75s | **0.0029 ms/sample** |

---

## 3. Held-Out Confusion Matrix Analysis

Evaluated on $N = 115,984$ completely unseen test URLs:

| True Ground Truth \ Predicted | Predicted Legitimate (0) | Predicted Phishing (1) | Total True Samples |
|---|---|---|---|
| **Actual Legitimate (0)** | **66,292 (TN)** | **1,523 (FP)** | 67,815 |
| **Actual Phishing (1)** | **2,881 (FN)** | **45,288 (TP)** | 48,169 |
| **Total Predicted** | 69,173 | 46,811 | **115,984** |

### Critical Diagnostic Metrics
- **False Alarm Rate (FPR):** $\frac{1,523}{67,815} = 2.25\%$ (Extremely low false positives on legitimate browsing traffic).
- **Phishing Miss Rate (FNR):** $\frac{2,881}{48,169} = 5.98\%$ (Over 94% of active phishing attacks successfully intercepted).
- **Specificity:** $97.75\%$
- **Negative Predictive Value (NPV):** $95.83\%$

---

## 4. Key Lexical Drivers (Feature Importance)

The top discriminatory features identified by the trained model include:
1. `entropy_url` / `entropy_hostname` / `entropy_domain`: High information entropy indicative of randomized algorithmically generated subdomains and obfuscated paths.
2. `path_length` & `url_depth`: Phishing attacks deeply nest directories to mimic legitimate portals (e.g., `/login/account/update/`).
3. `num_special_chars` & `num_percent`: Hex percent-encoding (`%20`, `%25`, `%2e`) used by phishers to bypass basic keyword filters.
4. `is_ip_address`: Raw IPv4 hostnames (`http://192.168...`) are strongly correlated with illicit infrastructure.
5. `is_suspicious_tld`: Free or low-cost TLDs (`.xyz`, `.top`, `.tk`, `.ml`, `.pw`) heavily utilized in mass phishing campaigns.
6. `multiple_http`: Embedding legitimate URLs inside query parameters (`?redirect=https://google.com`).
7. `contains_login` / `contains_secure` / `contains_bank` / `contains_account`: Targeted credential harvesting keywords.

---

## 5. Artifact Verification and Deployment Readiness

The following artifacts have been generated in `models/`:
- `best_model.joblib`: Production compressed model (1.54 MB).
- `feature_names.json`: Exact ordered 55-feature schema.
- `training_metrics.json`: Machine-readable evaluation metrics.
- `classification_report.json`: Precision, recall, and F1 per class.
- `confusion_matrix.png`: High-resolution confusion matrix graphic.
- `model_comparison.png`: Graphical benchmark chart comparing candidate models.
- `feature_importance.png`: Top-20 lexical feature rankings.
- `training_summary.md`: Concise model card.

Artifact verification confirms the model loads in under 35 milliseconds in a fresh Python process and computes predictions in < 3 microseconds per URL, satisfying all Render constraints.
