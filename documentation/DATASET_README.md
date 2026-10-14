# Phishing URL Features Dataset

## Overview
This dataset contains a large collection of URLs labeled as phishing or legitimate, along with a comprehensive set of engineered features.

The features capture structural, statistical, and infrastructure-related properties of URLs, making the dataset suitable for machine learning and cybersecurity tasks.

---

## Dataset Composition

- Total Samples: 579,920  
- Legitimate URLs: 339,074 (58.5%)  
- Phishing URLs: 240,846 (41.5%)

Each row represents a single URL instance with its corresponding label and feature values.

---

## Features

The dataset includes **74 numerical features**, grouped into three categories:

### 1. Lexical Features
Derived directly from the URL string:
- Length-based features
- Character counts
- Structural properties
- Entropy-based measures
- Pattern and keyword indicators

### 2. DNS Features
Describe domain resolution and infrastructure:
- Record availability (MX, TXT, NS)
- Time-to-live (TTL)
- IP-related attributes

### 3. WHOIS Features
Capture domain registration information:
- Domain age
- Expiration period
- Registration year
- Registrar-related attributes
- Privacy protection indicators

---

## Label Definition

- `0` → Legitimate  
- `1` → Phishing  

---

## Files

- `final_dataset.csv` → Main dataset  
- `feature_description.csv` → Feature descriptions  
- `dataset_info.txt` → Summary and statistics  

---

## Data Quality

- No missing (NaN) values  
- No infinite values  
- Features are precomputed and validated  
- Duplicate and inconsistent entries removed  

---

## Usage

This dataset can be used for:

- Phishing detection  
- Binary classification tasks  
- Machine learning benchmarking  
- Feature importance analysis  
- Cybersecurity research  

---

## Notes

- No predefined train/test split is included  
- Users can apply their own preprocessing and splitting strategies  
- DNS and WHOIS-based features may change over time  

---

## License

This dataset is released under the **CC BY 4.0 License**.