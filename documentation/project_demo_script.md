# 5-Minute Project Demonstration Script — PhishGuard AI

Follow this script to demonstrate the project to professors, evaluators, or interviewers.

---

### Step 1: System Startup (30 seconds)
1. Open terminal and run:
   ```bash
   uvicorn src.backend.main:app --reload --port 8000
   ```
2. Open web browser to `http://localhost:8000`.
3. Highlight that the React frontend is served directly by the FastAPI backend, with live health status showing the operational XGBoost model.

---

### Step 2: Overview & Model Evaluation Dashboard (60 seconds)
1. Point to the **Overview Dashboard**:
   - Show the verified held-out test accuracy (**96.20%**) and F1-score (**95.36%**).
   - Emphasize that this was trained on a massive, verified dataset of **579,920 samples** with zero data leakage.
2. Navigate to **Model Evaluation**:
   - Show the candidate model comparison table (Logistic Regression vs HistGradientBoosting vs XGBoost).
   - Show the held-out confusion matrix (66,292 True Negatives, 45,288 True Positives).

---

### Step 3: Real-Time URL Scanner (90 seconds)
1. Navigate to **URL Scanner**.
2. **Scan a legitimate URL:**
   - Input: `https://en.wikipedia.org/wiki/Computer_network`
   - Click **Analyze URL**.
   - Result: **LEGITIMATE** with low risk score and < 5ms CPU inference time.
3. **Scan a synthetic phishing URL:**
   - Input: `http://paypal-security-verification.update.xyz/login.php`
   - Result: **PHISHING** (100.0% Risk).
   - Show the detected indicators: suspicious `.xyz` TLD, `login` keyword, abnormal entropy.
   - Show the 55 extracted deterministic lexical features in the table below.

---

### Step 4: Computer Networks Features (90 seconds)
1. Click **Inspect Domain DNS** or navigate to **Network Monitor**:
   - Input `google.com`. Click **Lookup DNS**.
   - Show the resolved IPv4 (A) and IPv6 (AAAA) addresses and lookup duration.
   - Explain how DNS resolves hostnames to IP addresses without unsafe webpage rendering.
2. Navigate to **Firewall Simulator**:
   - Add a rule to block `evil-login-portal.top`.
   - Return to URL Scanner and scan `http://evil-login-portal.top/signin`.
   - Show the badge: **BLOCKED BY FIREWALL**!
3. Navigate to **Event History**:
   - Show the chronological audit trail of scans, DNS lookups, and blocked firewall requests.

---

### Step 5: Wrap-up & Q&A (30 seconds)
- Summarize that the application fulfills both Computer Networks requirements (client-server, DNS, latency, simulated firewall) and Cybersecurity ML requirements (>95% test accuracy, zero leakage, reproducible pipeline).
