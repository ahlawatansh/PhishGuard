# Model Training & Evaluation Summary — PhishGuard AI

- **Trained Model:** `XGBoost Classifier`
- **Training Timestamp:** 2026-10-13 16:39:29 UTC
- **Dataset:** `archive (21)/final_dataset.csv` (579,920 deduplicated samples)
- **Held-Out Test Set Size:** 115,984 samples (20% stratified)
- **Features Extracted:** 55 deterministic URL-only lexical features (zero scraping, zero leakage)

## Measured Test Metrics

- **Test Accuracy:** **96.20%**
- **Test Precision (Phishing):** **96.75%**
- **Test Recall (Phishing):** **94.02%**
- **Test F1-Score (Phishing):** **95.36%**
- **ROC-AUC Score:** **0.9930**

## Confusion Matrix Breakdown

- **True Negatives (Legitimate Correct):** 66,292
- **False Positives (Benign Flagged as Phishing):** 1,523
- **False Negatives (Phishing Missed):** 2,881
- **True Positives (Phishing Correctly Blocked):** 45,288

## Candidate Model Comparison

| Model | Accuracy | Precision | Recall | F1-Score | Fit Time (s) | Latency (ms/sample) |
|---|---|---|---|---|---|---|
| Logistic Regression | 91.62% | 91.49% | 88.01% | 89.72% | 2.96s | 0.0004 ms |
| HistGradientBoosting | 95.28% | 95.54% | 92.99% | 94.24% | 18.48s | 0.0047 ms |
| XGBoost Classifier | 96.20% | 96.75% | 94.02% | 95.36% | 8.75s | 0.0029 ms |
