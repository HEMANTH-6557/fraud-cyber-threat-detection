"""
Dataset Acquisition and Harmonization Script.
Downloads, validates, cleans, deduplicates, and caches authentic security datasets:
1. Financial Transactions: PaySim Mobile Money / Banking Wire Transfer Fraud (50,000+ samples)
2. Cyber Intrusion & Auth: KDD-Cup 99 (50,000 samples) + SQL Injection Payloads (50,570 samples)
3. Phishing & Email Threats: UCI Phishing Websites (11,055 samples) + UCI Spambase (4,601 samples)
"""

import os
import sys
import json
import urllib.request
import numpy as np
import pandas as pd
from sklearn.datasets import fetch_openml, fetch_kddcup99

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT_DIR, "data")
EXPANDED_DIR = os.path.join(DATA_DIR, "expanded_data")
os.makedirs(EXPANDED_DIR, exist_ok=True)

def download_financial_dataset(n_samples: int = 50000) -> pd.DataFrame:
    """
    Downloads authentic PaySim financial fraud transactions benchmark.
    Schema matches project financial telemetry:
    amount, user_name, merchant, merchant_category, is_fraud
    """
    print(f"\n[1/4] Fetching Financial Fraud Dataset (PaySim)...")
    cache_path = os.path.join(EXPANDED_DIR, "financial_fraud_expanded.csv")
    if os.path.exists(cache_path):
        df = pd.read_csv(cache_path)
        print(f"      Loaded cached financial dataset: {len(df):,} samples.")
        return df

    url = "https://huggingface.co/datasets/rohan-chandrashekar/credit_fraud_detection/resolve/main/data/validation-00000-of-00001.parquet"
    print(f"      Downloading from Hugging Face repository: {url}")
    df_raw = pd.read_parquet(url)
    
    # Stratified sampling to preserve fraud ratio while staying computationally optimal
    fraud_df = df_raw[df_raw["isFraud"] == 1]
    benign_df = df_raw[df_raw["isFraud"] == 0]
    
    n_fraud = min(len(fraud_df), int(n_samples * 0.15))
    n_benign = min(len(benign_df), n_samples - n_fraud)
    
    sampled_fraud = fraud_df.sample(n=n_fraud, random_state=42)
    sampled_benign = benign_df.sample(n=n_benign, random_state=42)
    df_sampled = pd.concat([sampled_benign, sampled_fraud]).sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    # Map to project telemetry schema
    df_clean = pd.DataFrame()
    df_clean["tx_id"] = [f"TXN-EXP-{i:06d}" for i in range(len(df_sampled))]
    df_clean["amount"] = df_sampled["amount"].astype(float)
    df_clean["account_id"] = [f"ACC-{str(orig)[:6]}" for orig in df_sampled["nameOrig"]]
    df_clean["user_name"] = [f"user_{str(orig)[:5]}" for orig in df_sampled["nameOrig"]]
    df_clean["merchant"] = [f"Merchant_{str(dest)[:5]}" for dest in df_sampled["nameDest"]]
    df_clean["old_balance_orig"] = df_sampled["oldBalanceOrig"].astype(float)
    df_clean["new_balance_orig"] = df_sampled["newBalanceOrig"].astype(float)
    df_clean["old_balance_dest"] = df_sampled["oldBalanceDest"].astype(float)
    df_clean["new_balance_dest"] = df_sampled["newBalanceDest"].astype(float)
    
    # Infer category from transaction action columns
    cat_cols = [c for c in df_sampled.columns if c.startswith("action__")]
    categories = []
    for idx, row in df_sampled.iterrows():
        matched = False
        for c in cat_cols:
            if row[c] == 1:
                categories.append(c.replace("action__", "").replace("_", " ").title())
                matched = True
                break
        if not matched:
            categories.append("Wire Transfer")
    df_clean["merchant_category"] = categories
    df_clean["is_fraud"] = df_sampled["isFraud"].astype(int)

    # Deduplication and null check
    df_clean = df_clean.drop_duplicates(subset=["amount", "account_id", "merchant", "old_balance_orig"]).reset_index(drop=True)
    df_clean = df_clean.dropna().reset_index(drop=True)
    
    df_clean.to_csv(cache_path, index=False)
    print(f"      Saved cleaned financial dataset to: {cache_path}")
    print(f"      Total unique samples: {len(df_clean):,} | Benign: {sum(df_clean['is_fraud']==0):,} | Fraud: {sum(df_clean['is_fraud']==1):,}")
    return df_clean

def download_cyber_intrusion_dataset(n_samples: int = 50000) -> pd.DataFrame:
    """
    Downloads authentic DARPA/KDD-Cup 99 network intrusion & auth log telemetry.
    Labels: 0 = Benign/Normal, 1 = Attack (Brute Force, R2L, U2R, Probe, DoS).
    """
    print(f"\n[2/4] Fetching Cyber Intrusion & Auth Dataset (KDD-Cup 99)...")
    cache_path = os.path.join(EXPANDED_DIR, "cyber_intrusion_expanded.csv")
    if os.path.exists(cache_path):
        df = pd.read_csv(cache_path)
        print(f"      Loaded cached cyber intrusion dataset: {len(df):,} samples.")
        return df

    kdd = fetch_kddcup99(percent10=True, as_frame=True)
    df_raw = kdd.frame
    
    # Decode byte strings
    for col in df_raw.select_dtypes(include=[object]).columns:
        df_raw[col] = df_raw[col].apply(lambda x: x.decode('utf-8', errors='ignore') if isinstance(x, bytes) else str(x))
    
    target_col = "labels" if "labels" in df_raw.columns else df_raw.columns[-1]
    df_raw["is_attack"] = (df_raw[target_col] != "normal.").astype(int)
    
    # Stratified sample
    norm_df = df_raw[df_raw["is_attack"] == 0]
    atk_df = df_raw[df_raw["is_attack"] == 1]
    
    n_norm = min(len(norm_df), int(n_samples * 0.60))
    n_atk = min(len(atk_df), n_samples - n_norm)
    
    sampled_norm = norm_df.sample(n=n_norm, random_state=42)
    sampled_atk = atk_df.sample(n=n_atk, random_state=42)
    df_sampled = pd.concat([sampled_norm, sampled_atk]).sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    # Drop duplicates
    df_sampled = df_sampled.drop_duplicates().reset_index(drop=True)
    df_sampled.to_csv(cache_path, index=False)
    print(f"      Saved cleaned cyber intrusion dataset to: {cache_path}")
    print(f"      Total unique samples: {len(df_sampled):,} | Normal: {sum(df_sampled['is_attack']==0):,} | Attack: {sum(df_sampled['is_attack']==1):,}")
    return df_sampled

def download_sql_injection_dataset() -> pd.DataFrame:
    """
    Downloads authentic SQL injection web attack payloads dataset.
    Labels: 0 = Benign query, 1 = Malicious SQLi payload.
    """
    print(f"\n[3/4] Fetching SQL Injection & Web Exploit Dataset...")
    cache_path = os.path.join(EXPANDED_DIR, "sql_injection_expanded.csv")
    if os.path.exists(cache_path):
        df = pd.read_csv(cache_path)
        print(f"      Loaded cached SQL injection dataset: {len(df):,} samples.")
        return df

    url = "https://huggingface.co/datasets/firdhokk/autotrain-data-sql-injection/resolve/main/raw/SQL_I.csv"
    print(f"      Downloading from Hugging Face repository: {url}")
    df = pd.read_csv(url)
    df = df.rename(columns={"Data": "payload", "Label": "is_attack"})
    df = df.dropna().drop_duplicates(subset=["payload"]).reset_index(drop=True)
    df["is_attack"] = df["is_attack"].astype(int)
    df.to_csv(cache_path, index=False)
    print(f"      Saved cleaned SQL injection dataset to: {cache_path}")
    print(f"      Total unique samples: {len(df):,} | Benign: {sum(df['is_attack']==0):,} | SQLi: {sum(df['is_attack']==1):,}")
    return df

def download_phishing_datasets() -> tuple:
    """
    Downloads UCI Phishing Websites (did=4534) and UCI Spambase (did=44).
    """
    print(f"\n[4/4] Fetching Phishing & Email Threat Datasets (UCI Phishing + Spambase)...")
    cache_phish = os.path.join(EXPANDED_DIR, "phishing_websites_expanded.csv")
    cache_spam = os.path.join(EXPANDED_DIR, "spambase_email_expanded.csv")
    
    if os.path.exists(cache_phish) and os.path.exists(cache_spam):
        df_phish = pd.read_csv(cache_phish)
        df_spam = pd.read_csv(cache_spam)
        print(f"      Loaded cached Phishing: {len(df_phish):,} and Spambase: {len(df_spam):,} samples.")
        return df_phish, df_spam

    # 1. PhishingWebsites
    pw = fetch_openml(data_id=4534, as_frame=True, parser='auto')
    df_pw = pw.frame
    target_col = pw.target_names[0] if pw.target_names else df_pw.columns[-1]
    # -1 is legitimate, 1 is phishing -> convert to 0 (legitimate) and 1 (phishing)
    df_pw["is_phishing"] = (df_pw[target_col].astype(str).str.strip() == "1").astype(int)
    df_pw = df_pw.drop_duplicates().reset_index(drop=True)
    df_pw.to_csv(cache_phish, index=False)

    # 2. Spambase
    sb = fetch_openml(data_id=44, as_frame=True, parser='auto')
    df_sb = sb.frame
    target_sb = sb.target_names[0] if sb.target_names else df_sb.columns[-1]
    df_sb["is_threat"] = (df_sb[target_sb].astype(str).str.strip() == "1").astype(int)
    df_sb = df_sb.drop_duplicates().reset_index(drop=True)
    df_sb.to_csv(cache_spam, index=False)

    print(f"      Saved UCI Phishing dataset to: {cache_phish} ({len(df_pw):,} samples)")
    print(f"      Saved UCI Spambase dataset to: {cache_spam} ({len(df_sb):,} samples)")
    return df_pw, df_sb

def download_all():
    print("=" * 80)
    print("  EXPANDED SECURITY DATASET ACQUISITION & INTEGRATION PIPELINE")
    print("=" * 80)
    df_fin = download_financial_dataset(n_samples=50000)
    df_cyber = download_cyber_intrusion_dataset(n_samples=50000)
    df_sqli = download_sql_injection_dataset()
    df_phish, df_spam = download_phishing_datasets()
    
    total_samples = len(df_fin) + len(df_cyber) + len(df_sqli) + len(df_phish) + len(df_spam)
    print("\n" + "=" * 80)
    print(f"  DATASET ACQUISITION COMPLETE: {total_samples:,} TOTAL UNIQUE SAMPLES ACQUIRED")
    print(f"  - Financial Transactions (PaySim):   {len(df_fin):,} samples")
    print(f"  - Cyber Intrusion (KDD-Cup 99):      {len(df_cyber):,} samples")
    print(f"  - SQL Injection Payloads (SQL_I):    {len(df_sqli):,} samples")
    print(f"  - Phishing Websites (UCI 4534):      {len(df_phish):,} samples")
    print(f"  - Email Threats (UCI Spambase 44):   {len(df_spam):,} samples")
    print("=" * 80)

if __name__ == "__main__":
    download_all()
