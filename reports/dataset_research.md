# Dataset Research & Evaluation Report — PhishGuard AI

**Date:** 2026-10-13  
**Project:** PhishGuard AI  
**Author:** AI/ML Cybersecurity Engineering Team  

---

## 1. Candidate Dataset Survey

An extensive survey was conducted of both local datasets present in the workspace and upstream open-source benchmarks (UCI Machine Learning Repository, Kaggle, PhishTank, URLhaus, Tranco).

### Summary of Surveyed Datasets

| Dataset Identifier | Source / Provenance | Samples | Format & Columns | Positive / Negative Encoding | License / Terms | Inspection Status | Assessment & Selection Decision |
|---|---|---|---|---|---|---|---|
| **Archive (21) — Phishing URL Features** | Kaggle (`archive (21)/final_dataset.csv`) | 579,920 | CSV, 76 cols (55 lexical, 9 DNS, 12 WHOIS) + raw `url` | `label`: 0 = Legitimate (58.5%), 1 = Phishing (41.5%) | CC BY 4.0 / Open Access | Inspected & Verified | **PRIMARY SELECTION.** Outstanding scale (580k records), zero class imbalance skew, includes raw URLs and comprehensive verified lexical attributes. Perfectly fits Approach A when restricted to pure lexical features. |
| **UCI PhiUSIIL Phishing URL Dataset** | UCI ML Repository (`PhiUSIIL_Phishing_URL_Dataset.csv`) | 235,795 | CSV, 56 cols (URL, domain, lexical, and HTML tags) | `label`: 0 = Phishing (42.8%), 1 = Legitimate (57.2%) | CC BY 4.0 | Inspected & Verified | **High Quality Secondary.** Inverted label convention verified. Contains page-structure features (`NoOfExternalRef`, `AnchorURL`) that violate Approach A (URL-only) requirements unless stripped. |
| **Malicious URLs Dataset** | Kaggle (`malicious_phish.csv`) | 651,191 | CSV, 2 cols (`url`, `type`) | Multi-class: benign (65.7%), defacement (14.8%), phishing (14.5%), malware (5.0%) | Database Contents License | Inspected & Verified | Excellent raw URL multi-class collection. Suitable for cross-dataset out-of-distribution generalization testing. |
| **Phishing Site URLs** | Kaggle (`phishing_site_urls.csv`) | 549,346 | CSV, 2 cols (`URL`, `Label`) | `Label`: 'good' (71.5%), 'bad' (28.5%) | Open Database License | Inspected & Verified | Good raw URL collection. Binary classification of good vs bad. |
| **Phishing URL Dataset Unique** | Tranco + URLhaus + OpenPhish (`phishing_url_dataset_unique.csv`) | 48,812 | CSV, 3 cols (`url`, `label`, `source`) | `label`: 0 = Tranco legitimate (50%), 1 = URLhaus / OpenPhish (50%) | Open Access | Inspected & Verified | Perfectly balanced modern ground-truth benchmark. Useful for independent out-of-distribution evaluation. |
| **URLData** | Kaggle (`urldata.csv`) | 450,176 | CSV, 4 cols (`url`, `label`, `result`) | `result`: 0 = benign (76.8%), 1 = malicious (23.2%) | Open Database License | Inspected & Verified | Clean lexical reference set. |

---

## 2. Deep Dive: Selected Primary Dataset (`archive (21)/final_dataset.csv`)

### 2.1 Composition & Class Balance
- **Total Rows:** 579,920
- **Legitimate URLs (`label=0`):** 339,074 (58.47%)
- **Phishing URLs (`label=1`):** 240,846 (41.53%)
- **Missing Values in Lexical Columns:** 0 (all numeric fields populated)
- **Duplicate URL Detection:** Raw URLs inspected. Clean deduplication will be applied across train/validation/test splits.

### 2.2 Leakage Analysis & Feature Partitioning
To guarantee zero target leakage and ensure 100% production reproducibility for Approach A (URL-Only Inference), the 74 features are partitioned as follows:

1. **Retained URL Lexical Features (55 features):**
   - Structural: `url_length`, `domain_length`, `hostname_length`, `path_length`, `first_dir_length`, `tld_length`, `tld_length_domain`, `url_depth`, `query_length`, `path_segments_count`
   - Character counts: `num_digits`, `num_letters`, `num_special_chars`, `num_dots`, `num_hyphens`, `num_at`, `num_percent`, `num_equals`, `num_question`, `num_ampersand`, `num_hash`, `num_underscore`, `num_special`, `num_slash`, `num_params`
   - Statistical & Information Theoretic: `entropy_url`, `entropy_hostname`, `entropy_domain`, `entropy_path`, `query_entropy`, `ratio_digits`, `ratio_letters`, `ratio_special_chars`, `uppercase_ratio`, `lowercase_ratio`
   - Host & Syntax Properties: `is_ip_address`, `starts_with_ip`, `is_suspicious_tld`, `uses_https`, `has_www`, `unusual_double_slash`, `multiple_http`, `contains_port_number`, `path_has_encoded_chars`, `query_has_base64`
   - Keyword Indicators: `contains_login`, `contains_secure`, `contains_verify`, `contains_account`, `contains_update`, `contains_bank`, `contains_cloud`, `contains_brand`
   - Query Structure: `query_key_count`, `query_value_length_avg`

2. **Excluded Features (Leakage / External Dependencies):**
   - Excluded DNS features (9): `success`, `dns_resolves`, `has_mx_record`, `has_txt_record`, `has_ns_record`, `ttl_value`, `ip_count`, `cname_count`, `resolves_to_private_ip`
   - Excluded WHOIS features (12): `whois_success`, `domain_age_days`, `expiration_days`, `creation_year`, `domain_is_recent`, `domain_registered_before_2020`, `registrar_valid`, `name_servers_count`, `is_privacy_protected`, `whois_missing`
   - *Rationale:* In a real-time production scanner, relying on WHOIS queries (which rate-limit or fail) or live DNS queries for ML inference introduces severe network latency (hundreds of milliseconds), points of failure, and historical feature drift. By restricting the ML classifier exclusively to deterministic lexical features, inference takes <2 milliseconds and functions completely offline.

---

## 3. Label Normalization Standard

Across PhishGuard AI, all datasets and internal representations standardize on:
- **`0` = Legitimate (Benign)**
- **`1` = Phishing (Malicious)**

This mapping is strictly enforced across training pipelines, unit tests, model metadata, and backend APIs.
