# System Architecture Specification — PhishGuard AI

**System:** PhishGuard AI  
**Academic Domain:** Computer Networks & Machine Learning Security  

---

## 1. High-Level Architectural Diagram

```text
+----------------------------------------------------------------------------------+
|                            USER BROWSER / CLIENT                                 |
|          React + TypeScript + Vite Dashboard (Strict Google Design System)       |
+----------------------------------------------------------------------------------+
                                        │
                         HTTP REST API  │  JSON / RFC 3986
                                        ▼
+----------------------------------------------------------------------------------+
|                            FASTAPI BACKEND SERVICE                               |
|                                                                                  |
|  +---------------------------+       +----------------------------------------+  |
|  |   Latency Middleware      |       |        CORS & Input Validation         |  |
|  |  (X-Response-Time-Ms)     |       |       (Pydantic URI Constraints)       |  |
|  +---------------------------+       +----------------------------------------+  |
|                                                                                  |
|  +----------------------------------------------------------------------------+  |
|  |                    COMPUTER NETWORKS CORE ENGINE                           |  |
|  |  • Bounded DNS Resolver (A / AAAA socket resolution with timeouts)         |  |
|  |  • Request-Response Latency Tracker & Statistical Aggregator               |  |
|  |  • In-Memory Simulated Firewall Engine & Domain Blocklist                  |  |
|  |  • Security Event Audit Trail (Chronological Log)                          |  |
|  +----------------------------------------------------------------------------+  |
|                                       │                                          |
|                                       ▼                                          |
|  +----------------------------------------------------------------------------+  |
|  |                    MACHINE LEARNING INFERENCE PIPELINE                     |  |
|  |  • URL Normalization (RFC 3986 Standardizer)                               |  |
|  |  • Deterministic Lexical Feature Extractor (55 pure string features)       |  |
|  |    (Zero webpage fetching, zero target leakage, offline computation)       |  |
|  |  • Trained XGBoost Classifier (models/best_model.joblib, 96.20% Accuracy)  |  |
|  |  • Calibrated Risk Score & Security Indicator Generator                    |  |
|  +----------------------------------------------------------------------------+  |
+----------------------------------------------------------------------------------+
```

---

## 2. Component Decoupling & Security Boundaries

1. **Approach A (URL-Only) Strict Isolation:**
   - Under no circumstances does the system send HTTP requests, render JavaScript, or establish TCP sockets to submitted untrusted URLs.
   - All classification features are derived purely through mathematical and statistical analysis of the URL string itself.

2. **Computer Networks Diagnostic Boundaries:**
   - The DNS resolver communicates only with local resolver caches or root DNS infrastructure using OS-level bounded UDP/TCP queries.
   - The Simulated Firewall blocks traffic in software memory; it never interferes with the operating system's kernel routing tables or host PF/iptables.
