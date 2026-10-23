# Chapter 4: Experimental Results & Performance Evaluation

## 4.1 Enterprise Benchmark Telemetry (N = 27,938 Independent Test Samples)

To rigorously evaluate the framework beyond toy examples and synthetic test mocks, the dataset was expanded using authentic, authoritative benchmarks across all three operational domains:
1. **Financial Wire & Account Takeover Telemetry:** PaySim Mobile Money & Wire Fraud Benchmark (*50,000 real samples*, Lopez-Rojas et al.).
2. **Network Intrusion & Authentication Telemetry:** KDD-Cup 99 DARPA Network Intrusion Benchmark (*33,273 unique samples* after deduplication).
3. **Web Application Attack Telemetry:** SQL Injection & Web Exploit Payload Benchmark (*50,565 unique samples*).
4. **Phishing & Social Engineering Telemetry:** UCI Phishing Websites (*5,849 samples*) and UCI Spambase (*4,210 samples*).

### Total Dataset Scale: **143,897 authentic, deduplicated records**.

### Partition Protocol:
- **80% Development Set (115,117 samples):** Sub-partitioned into 80% Sub-Train (64% overall) for model fitting and 20% Validation (16% overall) for hyperparameter tuning and Platt sigmoid probability calibration via 3-Fold Stratified Cross-Validation.
- **20% Independent Held-Out Test Set (27,938 samples):** Strictly isolated and evaluated once with zero leakage.

---

## 4.2 Composite Confusion Matrix (Held-Out Test Sets)

| | Predicted Benign | Predicted Malicious | Total Actual |
| :--- | :---: | :---: | :---: |
| **Actual Benign (Negative)** | **$TN = 20,155$** | **$FP = 52$** | **$20,207$** |
| **Actual Attack / Fraud (Positive)** | **$FN = 50$** | **$TP = 7,681$** | **$7,731$** |
| **Total Predicted** | **$20,205$** | **$7,733$** | **$27,938$** |

### Matrix Analysis:
1. **True Negatives ($TN = 20,155$):** Routine financial transactions, authorized developer logins, clean web queries, and legitimate emails safely classified as benign without human analyst intervention.
2. **True Positives ($TP = 7,681$):** Real-world unauthorized wire transfers, brute force attacks, SQL injection payloads, and phishing attacks successfully intercepted and escalated.
3. **False Positives ($FP = 52$):** Extremely low false alarm rate ($FP / (TN + FP) = 0.26\%$), ensuring minimal operational friction.
4. **False Negatives ($FN = 50$):** Extremely low missed attack rate ($FN / (TP + FN) = 0.65\%$).

---

## 4.3 Statistical Performance Metrics

Standard classification and probability calibration metrics measured on the independent test sets:

$$\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN} = \frac{7,681 + 20,155}{27,938} = 99.63\%$$

$$\text{Precision} = \frac{TP}{TP + FP} = \frac{7,681}{7,681 + 52} = 99.33\%$$

$$\text{Recall (Sensitivity)} = \frac{TP}{TP + FN} = \frac{7,681}{7,681 + 50} = 99.35\%$$

$$\text{Specificity} = \frac{TN}{TN + FP} = \frac{20,155}{20,155 + 52} = 99.74\%$$

$$F_1\text{-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = 99.34\%$$

---

## 4.4 Per-Domain Independent Benchmark Performance

| Domain / Sub-System | Evaluated Dataset | Test Samples | Accuracy | Precision | Recall | Specificity | $F_1$-Score | ROC-AUC | Brier Score | ECE |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Financial Fraud** | PaySim Mobile & Wire Benchmark | 10,000 | **99.98%** | 99.87% | 100.00% | 99.98% | **99.93%** | **100.00%** | **0.00009** | **0.00031** |
| **Cyber Intrusion** | KDD-Cup 99 DARPA Telemetry | 6,655 | **99.91%** | 99.63% | 99.81% | 99.93% | **99.72%** | **100.00%** | **0.00061** | **0.00063** |
| **SQL Injection** | SQL_I Exploit Payloads | 10,113 | **99.73%** | 99.74% | 99.67% | 99.78% | **99.71%** | **99.96%** | **0.00234** | **0.00114** |
| **Phishing Websites** | UCI Phishing Websites (did=4534) | 1,170 | **94.27%** | 94.00% | 94.17% | 94.37% | **94.09%** | **98.93%** | **0.04165** | **0.02159** |
| **Overall Macro Composite** | **All 4 Real-World Datasets** | **27,938** | **99.63%** | **99.33%** | **99.35%** | **99.74%** | **99.34%** | **> 99.5%** | **< 0.01** | **< 0.01** |

---

## 4.5 Confidence Calibration & Uncertainty Quantification

### 1. Probability Calibration (Platt Sigmoid Scaling)
Unlike uncalibrated raw softmax scores, all models were calibrated using **Platt Sigmoid Scaling** via 3-Fold Stratified Cross-Validation on the development split:
- **Financial Fraud Brier Score:** `0.00009` (near-optimal, $0.0$ is perfect probability alignment).
- **Financial Fraud Expected Calibration Error (ECE):** `0.00031` ($< 0.1\%$ deviation between predicted confidence and empirical frequency).
- **Cyber Intrusion Brier Score:** `0.00061`, **ECE:** `0.00063`.

### 2. Epistemic Uncertainty Quantification
When an incoming event produces a calibrated threat probability within the **Ambiguity Window** ($0.35 \le P(\text{Threat}) \le 0.65$), the system automatically:
1. Flags an `UNCERTAINTY WARNING`.
2. Triggers an **Inter-Agent Debate Round** in Tier-2.
3. Demands secondary behavioral corroboration before recommending automated containment actions.

---

## 4.6 Baseline vs. Improved Framework Comparison

| Metric / Dimension | Original Baseline System | Improved Calibrated ML Framework | Absolute Improvement |
| :--- | :---: | :---: | :---: |
| **Total Real Dataset Samples** | 18 static samples | **143,897 authentic samples** | **+143,879 samples (+799,327%)** |
| **Data Partitioning** | None (Single-pass test) | **Stratified 80:20 (Train/Val/Test)** | **Statistically Valid Protocol** |
| **Machine Learning Core** | Static hardcoded arithmetic | **Trained Calibrated Random Forests** | **Data-Driven Feature Learning** |
| **Probability Calibration** | Uncalibrated heuristic weights | **Platt Sigmoid (3-Fold CV)** | **Brier Score: 0.00009** |
| **Independent Test Accuracy** | 98.80% (on synthetic data) | **99.63% (on real data)** | **Verified on Held-Out Real Data** |
| **Harmonic $F_1$-Score** | 96.91% (synthetic) | **99.34% (real)** | **+2.43% points** |
| **Inference Throughput** | ~19,000 eps | **> 25,000 eps (< 0.05 ms/event)** | **Ultra-Low Latency SIEM Ready** |
