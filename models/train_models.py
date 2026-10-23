"""
Enterprise ML Training, Calibration, and Model Serialization Pipeline.
Trains, validates, calibrates, and evaluates machine learning models across:
1. Financial Transactions: PaySim Fraud Detection (50,000 samples)
2. Cyber Intrusion & Network Auth: KDD-Cup 99 (33,273 samples)
3. Cyber Web Attacks: SQL Injection Payloads (50,565 samples)
4. Phishing & Email Threats: UCI Phishing Websites (5,849 samples) + UCI Spambase (4,210 samples)

Evaluation Protocol:
- Stratified 80:20 Partition (80% Development, 20% Held-Out Independent Test)
- Dev set partitioned into 80% Sub-Train (64% overall) and 20% Validation (16% overall)
- Model selection performed strictly on Validation set
- Probability Calibration (Platt Sigmoid / Isotonic via 3-Fold Stratified CV on Dev set)
- Independent Test set evaluated strictly once with full metrics
"""

import os
import sys
import time
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    brier_score_loss
)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT_DIR, "data", "expanded_data")
MODELS_DIR = os.path.join(ROOT_DIR, "models")
ARTIFACTS_DIR = os.path.join(MODELS_DIR, "artifacts")
RESULTS_DIR = os.path.join(ROOT_DIR, "results")

os.makedirs(ARTIFACTS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

def compute_ece(y_true, y_prob, n_bins=10):
    """Computes Expected Calibration Error (ECE)."""
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        bin_mask = (y_prob >= bin_edges[i]) & (y_prob < bin_edges[i + 1])
        if np.sum(bin_mask) > 0:
            bin_acc = np.mean(y_true[bin_mask])
            bin_conf = np.mean(y_prob[bin_mask])
            bin_weight = np.sum(bin_mask) / len(y_true)
            ece += bin_weight * np.abs(bin_acc - bin_conf)
    return float(ece)

def evaluate_predictions(y_true, y_pred, y_prob, start_time=None) -> Dict[str, Any]:
    """Computes all comprehensive classification and calibration metrics."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    f1 = f1_score(y_true, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_true, y_prob) if len(np.unique(y_true)) > 1 else 0.5
    pr_auc = average_precision_score(y_true, y_prob) if len(np.unique(y_true)) > 1 else 0.0
    brier = brier_score_loss(y_true, y_prob)
    ece = compute_ece(np.array(y_true), np.array(y_prob))

    metrics = {
        "accuracy": round(float(acc) * 100, 2),
        "precision": round(float(prec) * 100, 2),
        "recall": round(float(rec) * 100, 2),
        "specificity": round(float(spec) * 100, 2),
        "f1_score": round(float(f1) * 100, 2),
        "roc_auc": round(float(roc_auc) * 100, 2),
        "pr_auc": round(float(pr_auc) * 100, 2),
        "brier_score": round(float(brier), 4),
        "expected_calibration_error": round(float(ece), 4),
        "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)}
    }
    if start_time:
        latency_ms = ((time.time() - start_time) / len(y_true)) * 1000
        metrics["inference_latency_ms_per_sample"] = round(latency_ms, 4)
    return metrics

# ==============================================================================
# 1. FINANCIAL FRAUD MODEL (PaySim Benchmark)
# ==============================================================================
def train_financial_fraud_model():
    print("\n" + "=" * 80)
    print("  [1/4] TRAINING FINANCIAL FRAUD DETECTOR (PAYSIM BENCHMARK)")
    print("=" * 80)

    data_path = os.path.join(DATA_DIR, "financial_fraud_expanded.csv")
    df = pd.read_csv(data_path)
    total_samples = len(df)
    
    # Feature Engineering
    df["balance_orig_diff"] = df["old_balance_orig"] - df["new_balance_orig"]
    df["balance_dest_diff"] = df["new_balance_dest"] - df["old_balance_dest"]
    df["orig_drain_ratio"] = df["amount"] / (df["old_balance_orig"] + 1.0)
    df["dest_gain_ratio"] = df["amount"] / (df["new_balance_dest"] + 1.0)
    
    numeric_features = [
        "amount", "old_balance_orig", "new_balance_orig",
        "old_balance_dest", "new_balance_dest",
        "balance_orig_diff", "balance_dest_diff",
        "orig_drain_ratio", "dest_gain_ratio"
    ]
    categorical_features = ["merchant_category"]
    
    X = df[numeric_features + categorical_features]
    y = df["is_fraud"].values

    # Stratified 80/20 Partition
    X_dev, X_test, y_dev, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    # Sub-partition Dev into 80% Train, 20% Val
    X_train, X_val, y_train, y_val = train_test_split(
        X_dev, y_dev, test_size=0.20, random_state=42, stratify=y_dev
    )

    print(f"  Dataset Partition:")
    print(f"  - Total Unique Samples: {total_samples:,}")
    print(f"  - Sub-Train (64%):      {len(X_train):,} samples (Fraud: {sum(y_train==1):,})")
    print(f"  - Validation (16%):     {len(X_val):,} samples (Fraud: {sum(y_val==1):,})")
    print(f"  - Independent Test (20%): {len(X_test):,} samples (Fraud: {sum(y_test==1):,})")

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), numeric_features),
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features)
        ]
    )

    # 1. Baseline: Logistic Regression
    print("\n  Evaluating Models on Validation Set:")
    pipe_baseline = Pipeline([
        ("prep", preprocessor),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=500, random_state=42))
    ])
    pipe_baseline.fit(X_train, y_train)
    val_prob_base = pipe_baseline.predict_proba(X_val)[:, 1]
    val_f1_base = f1_score(y_val, (val_prob_base >= 0.5).astype(int))
    print(f"  -> Baseline (Logistic Regression) Val F1: {val_f1_base * 100:.2f}%")

    # 2. Candidate: Random Forest Classifier
    pipe_rf = Pipeline([
        ("prep", preprocessor),
        ("clf", RandomForestClassifier(n_estimators=100, class_weight="balanced", n_jobs=-1, random_state=42))
    ])
    pipe_rf.fit(X_train, y_train)
    val_prob_rf = pipe_rf.predict_proba(X_val)[:, 1]
    val_f1_rf = f1_score(y_val, (val_prob_rf >= 0.5).astype(int))
    print(f"  -> Candidate (Random Forest Classifier) Val F1: {val_f1_rf * 100:.2f}%")

    # Select best model on validation
    best_pipe = pipe_rf if val_f1_rf >= val_f1_base else pipe_baseline
    best_name = "RandomForestClassifier" if best_pipe == pipe_rf else "LogisticRegression"
    print(f"  Selected Best Model based on Validation: {best_name}")

    # 3. Probability Calibration via Platt Scaling (Sigmoid) with 3-Fold Stratified CV on Dev set
    print("\n  Calibrating Probabilities (Platt Sigmoid 3-Fold CV) on Dev Set...")
    calibrated_clf = CalibratedClassifierCV(estimator=best_pipe, method="sigmoid", cv=3)
    calibrated_clf.fit(X_dev, y_dev)

    # 4. Final Evaluation on Strictly Independent Test Set
    print("\n  Evaluating Best Calibrated Model on Independent Test Set (20% Held-Out)...")
    t0 = time.time()
    test_probs = calibrated_clf.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= 0.50).astype(int)
    test_metrics = evaluate_predictions(y_test, test_preds, test_probs, start_time=t0)

    print(f"  TEST ACCURACY:    {test_metrics['accuracy']}%")
    print(f"  TEST PRECISION:   {test_metrics['precision']}%")
    print(f"  TEST RECALL:      {test_metrics['recall']}%")
    print(f"  TEST SPECIFICITY: {test_metrics['specificity']}%")
    print(f"  TEST F1-SCORE:    {test_metrics['f1_score']}%")
    print(f"  TEST ROC-AUC:     {test_metrics['roc_auc']}%")
    print(f"  TEST PR-AUC:      {test_metrics['pr_auc']}%")
    print(f"  TEST BRIER SCORE: {test_metrics['brier_score']}")
    print(f"  TEST ECE:         {test_metrics['expected_calibration_error']}")
    print(f"  CONFUSION MATRIX: {test_metrics['confusion_matrix']}")
    print(f"  INFERENCE SPEED:  {test_metrics['inference_latency_ms_per_sample']} ms/sample")

    # Serialize Model Artifact
    artifact_file = os.path.join(ARTIFACTS_DIR, "financial_fraud_model.joblib")
    joblib.dump(calibrated_clf, artifact_file)
    print(f"  Saved calibrated model artifact to: {artifact_file}")

    return {
        "domain": "FINANCIAL",
        "dataset_name": "PaySim Financial Fraud Detection",
        "sample_counts": {
            "total": total_samples,
            "train": len(X_train),
            "val": len(X_val),
            "test": len(X_test)
        },
        "best_algorithm": best_name,
        "calibration_method": "Platt Sigmoid Scaling (3-Fold CV on Dev set)",
        "test_metrics": test_metrics
    }

# ==============================================================================
# 2. CYBER INTRUSION & AUTH LOG MODEL (KDD-Cup 99 Benchmark)
# ==============================================================================
def train_cyber_intrusion_model():
    print("\n" + "=" * 80)
    print("  [2/4] TRAINING CYBER INTRUSION & AUTH DETECTOR (KDD-CUP 99 BENCHMARK)")
    print("=" * 80)

    data_path = os.path.join(DATA_DIR, "cyber_intrusion_expanded.csv")
    df = pd.read_csv(data_path)
    total_samples = len(df)

    y = df["is_attack"].values
    target_cols = ["labels", "is_attack"]
    feature_cols = [c for c in df.columns if c not in target_cols]
    
    numeric_cols = []
    categorical_cols = []
    for c in feature_cols:
        if pd.api.types.is_numeric_dtype(df[c]):
            numeric_cols.append(c)
        else:
            categorical_cols.append(c)

    X = df[feature_cols]

    # Stratified 80/20 Partition
    X_dev, X_test, y_dev, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_dev, y_dev, test_size=0.20, random_state=42, stratify=y_dev
    )

    print(f"  Dataset Partition:")
    print(f"  - Total Unique Samples: {total_samples:,}")
    print(f"  - Sub-Train (64%):      {len(X_train):,} samples (Attacks: {sum(y_train==1):,})")
    print(f"  - Validation (16%):     {len(X_val):,} samples (Attacks: {sum(y_val==1):,})")
    print(f"  - Independent Test (20%): {len(X_test):,} samples (Attacks: {sum(y_test==1):,})")

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), numeric_cols),
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols)
        ]
    )

    # 1. Baseline: Logistic Regression
    pipe_baseline = Pipeline([
        ("prep", preprocessor),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=500, random_state=42))
    ])
    pipe_baseline.fit(X_train, y_train)
    val_prob_base = pipe_baseline.predict_proba(X_val)[:, 1]
    val_f1_base = f1_score(y_val, (val_prob_base >= 0.5).astype(int))
    print(f"  -> Baseline (Logistic Regression) Val F1: {val_f1_base * 100:.2f}%")

    # 2. Candidate: Random Forest Classifier
    pipe_rf = Pipeline([
        ("prep", preprocessor),
        ("clf", RandomForestClassifier(n_estimators=100, class_weight="balanced", n_jobs=-1, random_state=42))
    ])
    pipe_rf.fit(X_train, y_train)
    val_prob_rf = pipe_rf.predict_proba(X_val)[:, 1]
    val_f1_rf = f1_score(y_val, (val_prob_rf >= 0.5).astype(int))
    print(f"  -> Candidate (Random Forest Classifier) Val F1: {val_f1_rf * 100:.2f}%")

    best_pipe = pipe_rf if val_f1_rf >= val_f1_base else pipe_baseline
    best_name = "RandomForestClassifier" if best_pipe == pipe_rf else "LogisticRegression"
    print(f"  Selected Best Model based on Validation: {best_name}")

    # Calibration on Dev Set with 3-Fold Stratified CV
    print("\n  Calibrating Probabilities (Platt Sigmoid 3-Fold CV) on Dev Set...")
    calibrated_clf = CalibratedClassifierCV(estimator=best_pipe, method="sigmoid", cv=3)
    calibrated_clf.fit(X_dev, y_dev)

    # Final Evaluation on Held-Out Test Set
    print("\n  Evaluating Best Calibrated Model on Independent Test Set (20% Held-Out)...")
    t0 = time.time()
    test_probs = calibrated_clf.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= 0.50).astype(int)
    test_metrics = evaluate_predictions(y_test, test_preds, test_probs, start_time=t0)

    print(f"  TEST ACCURACY:    {test_metrics['accuracy']}%")
    print(f"  TEST PRECISION:   {test_metrics['precision']}%")
    print(f"  TEST RECALL:      {test_metrics['recall']}%")
    print(f"  TEST SPECIFICITY: {test_metrics['specificity']}%")
    print(f"  TEST F1-SCORE:    {test_metrics['f1_score']}%")
    print(f"  TEST ROC-AUC:     {test_metrics['roc_auc']}%")
    print(f"  TEST PR-AUC:      {test_metrics['pr_auc']}%")
    print(f"  CONFUSION MATRIX: {test_metrics['confusion_matrix']}")
    print(f"  INFERENCE SPEED:  {test_metrics['inference_latency_ms_per_sample']} ms/sample")

    artifact_file = os.path.join(ARTIFACTS_DIR, "cyber_intrusion_model.joblib")
    joblib.dump(calibrated_clf, artifact_file)
    print(f"  Saved cyber intrusion model artifact to: {artifact_file}")

    return {
        "domain": "CYBER_LOG",
        "dataset_name": "KDD-Cup 99 Intrusion Telemetry",
        "sample_counts": {
            "total": total_samples,
            "train": len(X_train),
            "val": len(X_val),
            "test": len(X_test)
        },
        "best_algorithm": best_name,
        "calibration_method": "Platt Sigmoid Scaling (3-Fold CV on Dev set)",
        "test_metrics": test_metrics
    }

# ==============================================================================
# 3. SQL INJECTION & WEB EXPLOIT MODEL (SQL_I Benchmark)
# ==============================================================================
def train_sqli_payload_model():
    print("\n" + "=" * 80)
    print("  [3/4] TRAINING SQL INJECTION WEB EXPLOIT DETECTOR (SQL_I BENCHMARK)")
    print("=" * 80)

    data_path = os.path.join(DATA_DIR, "sql_injection_expanded.csv")
    df = pd.read_csv(data_path)
    total_samples = len(df)

    X = df["payload"].astype(str)
    y = df["is_attack"].values

    # Stratified 80/20 Partition
    X_dev, X_test, y_dev, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_dev, y_dev, test_size=0.20, random_state=42, stratify=y_dev
    )

    print(f"  Dataset Partition:")
    print(f"  - Total Unique Samples: {total_samples:,}")
    print(f"  - Sub-Train (64%):      {len(X_train):,} samples (SQLi: {sum(y_train==1):,})")
    print(f"  - Validation (16%):     {len(X_val):,} samples (SQLi: {sum(y_val==1):,})")
    print(f"  - Independent Test (20%): {len(X_test):,} samples (SQLi: {sum(y_test==1):,})")

    # Character n-gram TF-IDF Vectorizer
    vectorizer = TfidfVectorizer(ngram_range=(2, 4), analyzer="char", max_features=3000)

    # 1. Baseline: Logistic Regression
    pipe_baseline = Pipeline([
        ("tfidf", vectorizer),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=500, random_state=42))
    ])
    pipe_baseline.fit(X_train, y_train)
    val_prob_base = pipe_baseline.predict_proba(X_val)[:, 1]
    val_f1_base = f1_score(y_val, (val_prob_base >= 0.5).astype(int))
    print(f"  -> Baseline (TF-IDF + Logistic Regression) Val F1: {val_f1_base * 100:.2f}%")

    # 2. Candidate: Random Forest Classifier
    pipe_rf = Pipeline([
        ("tfidf", vectorizer),
        ("clf", RandomForestClassifier(n_estimators=50, class_weight="balanced", n_jobs=-1, random_state=42))
    ])
    pipe_rf.fit(X_train, y_train)
    val_prob_rf = pipe_rf.predict_proba(X_val)[:, 1]
    val_f1_rf = f1_score(y_val, (val_prob_rf >= 0.5).astype(int))
    print(f"  -> Candidate (TF-IDF + Random Forest) Val F1: {val_f1_rf * 100:.2f}%")

    best_pipe = pipe_rf if val_f1_rf >= val_f1_base else pipe_baseline
    best_name = "TF-IDF + RandomForest" if best_pipe == pipe_rf else "TF-IDF + LogisticRegression"
    print(f"  Selected Best Model based on Validation: {best_name}")

    # Calibration on Dev Set with 3-Fold Stratified CV
    print("\n  Calibrating Probabilities (Platt Sigmoid 3-Fold CV) on Dev Set...")
    calibrated_clf = CalibratedClassifierCV(estimator=best_pipe, method="sigmoid", cv=3)
    calibrated_clf.fit(X_dev, y_dev)

    # Final Evaluation on Independent Test Set
    print("\n  Evaluating Best Calibrated Model on Independent Test Set (20% Held-Out)...")
    t0 = time.time()
    test_probs = calibrated_clf.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= 0.50).astype(int)
    test_metrics = evaluate_predictions(y_test, test_preds, test_probs, start_time=t0)

    print(f"  TEST ACCURACY:    {test_metrics['accuracy']}%")
    print(f"  TEST PRECISION:   {test_metrics['precision']}%")
    print(f"  TEST RECALL:      {test_metrics['recall']}%")
    print(f"  TEST SPECIFICITY: {test_metrics['specificity']}%")
    print(f"  TEST F1-SCORE:    {test_metrics['f1_score']}%")
    print(f"  TEST ROC-AUC:     {test_metrics['roc_auc']}%")
    print(f"  TEST PR-AUC:      {test_metrics['pr_auc']}%")
    print(f"  CONFUSION MATRIX: {test_metrics['confusion_matrix']}")
    print(f"  INFERENCE SPEED:  {test_metrics['inference_latency_ms_per_sample']} ms/sample")

    artifact_file = os.path.join(ARTIFACTS_DIR, "sqli_payload_model.joblib")
    joblib.dump(calibrated_clf, artifact_file)
    print(f"  Saved SQLi payload model artifact to: {artifact_file}")

    return {
        "domain": "CYBER_SQLI",
        "dataset_name": "SQL Injection Exploit Benchmark (SQL_I)",
        "sample_counts": {
            "total": total_samples,
            "train": len(X_train),
            "val": len(X_val),
            "test": len(X_test)
        },
        "best_algorithm": best_name,
        "calibration_method": "Platt Sigmoid Scaling (3-Fold CV on Dev set)",
        "test_metrics": test_metrics
    }

# ==============================================================================
# 4. PHISHING & EMAIL THREAT MODEL (UCI Phishing + Spambase)
# ==============================================================================
def train_phishing_email_model():
    print("\n" + "=" * 80)
    print("  [4/4] TRAINING PHISHING & EMAIL THREAT DETECTOR (UCI BENCHMARKS)")
    print("=" * 80)

    # A: Phishing Websites Benchmark
    data_pw = os.path.join(DATA_DIR, "phishing_websites_expanded.csv")
    df_pw = pd.read_csv(data_pw)
    
    target_col = "is_phishing"
    feat_cols = [c for c in df_pw.columns if c not in [target_col, "Result"]]
    X_pw = df_pw[feat_cols]
    y_pw = df_pw[target_col].values

    X_dev_pw, X_test_pw, y_dev_pw, y_test_pw = train_test_split(
        X_pw, y_pw, test_size=0.20, random_state=42, stratify=y_pw
    )
    X_train_pw, X_val_pw, y_train_pw, y_val_pw = train_test_split(
        X_dev_pw, y_dev_pw, test_size=0.20, random_state=42, stratify=y_dev_pw
    )

    pipe_pw = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(n_estimators=100, class_weight="balanced", n_jobs=-1, random_state=42))
    ])
    pipe_pw.fit(X_train_pw, y_train_pw)
    cal_pw = CalibratedClassifierCV(estimator=pipe_pw, method="sigmoid", cv=3)
    cal_pw.fit(X_dev_pw, y_dev_pw)
    
    t0 = time.time()
    probs_pw = cal_pw.predict_proba(X_test_pw)[:, 1]
    preds_pw = (probs_pw >= 0.50).astype(int)
    metrics_pw = evaluate_predictions(y_test_pw, preds_pw, probs_pw, start_time=t0)
    joblib.dump(cal_pw, os.path.join(ARTIFACTS_DIR, "phishing_website_model.joblib"))

    # B: Spambase Email Threat Benchmark
    data_sb = os.path.join(DATA_DIR, "spambase_email_expanded.csv")
    df_sb = pd.read_csv(data_sb)
    
    target_sb = "is_threat"
    feat_sb = [c for c in df_sb.columns if c not in [target_sb, "class"]]
    X_sb = df_sb[feat_sb]
    y_sb = df_sb[target_sb].values

    X_dev_sb, X_test_sb, y_dev_sb, y_test_sb = train_test_split(
        X_sb, y_sb, test_size=0.20, random_state=42, stratify=y_sb
    )
    X_train_sb, X_val_sb, y_train_sb, y_val_sb = train_test_split(
        X_dev_sb, y_dev_sb, test_size=0.20, random_state=42, stratify=y_dev_sb
    )

    pipe_sb = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(n_estimators=100, class_weight="balanced", n_jobs=-1, random_state=42))
    ])
    pipe_sb.fit(X_train_sb, y_train_sb)
    cal_sb = CalibratedClassifierCV(estimator=pipe_sb, method="sigmoid", cv=3)
    cal_sb.fit(X_dev_sb, y_dev_sb)

    t1 = time.time()
    probs_sb = cal_sb.predict_proba(X_test_sb)[:, 1]
    preds_sb = (probs_sb >= 0.50).astype(int)
    metrics_sb = evaluate_predictions(y_test_sb, preds_sb, probs_sb, start_time=t1)
    joblib.dump(cal_sb, os.path.join(ARTIFACTS_DIR, "spambase_email_model.joblib"))

    print(f"  Phishing Websites (UCI 4534) Test Accuracy: {metrics_pw['accuracy']}% | F1: {metrics_pw['f1_score']}% | Latency: {metrics_pw['inference_latency_ms_per_sample']} ms")
    print(f"  Email Threats (UCI Spambase)  Test Accuracy: {metrics_sb['accuracy']}% | F1: {metrics_sb['f1_score']}% | Latency: {metrics_sb['inference_latency_ms_per_sample']} ms")

    return {
        "domain": "EMAIL_PHISHING",
        "dataset_name": "UCI PhishingWebsites & Spambase",
        "sample_counts": {
            "phishing_websites": {
                "total": len(df_pw),
                "train": len(X_train_pw),
                "val": len(X_val_pw),
                "test": len(X_test_pw)
            },
            "spambase_emails": {
                "total": len(df_sb),
                "train": len(X_train_sb),
                "val": len(X_val_sb),
                "test": len(X_test_sb)
            },
            "total_combined": len(df_pw) + len(df_sb)
        },
        "best_algorithm": "RandomForestClassifier (StandardScaled)",
        "calibration_method": "Platt Sigmoid Scaling (3-Fold CV on Dev set)",
        "test_metrics_phishing_websites": metrics_pw,
        "test_metrics_spambase_emails": metrics_sb
    }

def run_all_training():
    print("=" * 80)
    print("  PRODUCTION-GRADE ML TRAINING, CALIBRATION & INDEPENDENT TEST PIPELINE")
    print("=" * 80)
    
    start_all = time.time()
    m_fin = train_financial_fraud_model()
    m_cyber = train_cyber_intrusion_model()
    m_sqli = train_sqli_payload_model()
    m_phish = train_phishing_email_model()
    total_time = time.time() - start_all

    all_metadata = {
        "training_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_training_wallclock_seconds": round(total_time, 2),
        "hardware_environment": {
            "platform": sys.platform,
            "logical_cpu_cores": os.cpu_count(),
            "gpu_device": "NVIDIA GeForce RTX 3050 6GB Laptop GPU",
            "ram_capacity_gb": 15.64
        },
        "models": {
            "financial_fraud": m_fin,
            "cyber_intrusion": m_cyber,
            "sql_injection": m_sqli,
            "phishing_email": m_phish
        }
    }

    metadata_path = os.path.join(ARTIFACTS_DIR, "model_metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(all_metadata, f, indent=2)
    print(f"\n[OK] All trained models, calibrated pipelines, and metadata saved to: {ARTIFACTS_DIR}")
    print(f"   Metadata JSON: {metadata_path}")
    print(f"   Total Pipeline Runtime: {total_time:.2f}s")

if __name__ == "__main__":
    run_all_training()
