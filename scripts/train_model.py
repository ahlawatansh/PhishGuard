import os
import sys
import time
import json
import argparse
import numpy as np
import pandas as pd
import joblib

os.environ['MPLCONFIGDIR'] = os.path.expanduser('~/.cache/matplotlib_phishguard')
os.makedirs(os.environ['MPLCONFIGDIR'], exist_ok=True)
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

import xgboost as xgb

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.ml.feature_extractor import FEATURE_NAMES


def parse_args():
    default_dataset = "data/training/final_dataset.csv"
    if not os.path.exists(default_dataset) and os.path.exists("archive (21)/final_dataset.csv"):
        default_dataset = "archive (21)/final_dataset.csv"

    parser = argparse.ArgumentParser(description="Train PhishGuard AI URL Classification Model")
    parser.add_argument("--dataset", type=str, default=default_dataset, help="Path to CSV dataset")
    parser.add_argument("--max_records", type=int, default=None, help="Max records to load (None for all)")
    parser.add_argument("--test_size", type=float, default=0.2, help="Held-out test set fraction")
    parser.add_argument("--random_seed", type=int, default=42, help="Random state seed")
    parser.add_argument("--output_dir", type=str, default="models", help="Output directory for model artifacts")
    return parser.parse_args()


def load_and_preprocess_data(dataset_path: str, max_records: int = None, random_seed: int = 42):
    print(f"Loading dataset from: {dataset_path}")
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at: {dataset_path}")

    sample = pd.read_csv(dataset_path, nrows=5)
    target_col = 'label'
    if target_col not in sample.columns:
        raise ValueError(f"Target column '{target_col}' not found in dataset columns: {list(sample.columns)}")

    available_features = [f for f in FEATURE_NAMES if f in sample.columns]
    print(f"Verified {len(available_features)}/{len(FEATURE_NAMES)} lexical features available in dataset.")
    if len(available_features) != len(FEATURE_NAMES):
        missing = set(FEATURE_NAMES) - set(available_features)
        raise ValueError(f"Missing required lexical features in dataset: {missing}")

    cols_to_load = ['url', target_col] + FEATURE_NAMES
    t0 = time.time()
    df = pd.read_csv(dataset_path, usecols=cols_to_load, nrows=max_records)
    load_time = time.time() - t0
    print(f"Loaded {len(df):,} records in {load_time:.2f}s.")

    orig_len = len(df)
    df = df.drop_duplicates(subset=['url'])
    print(f"Deduplicated: {orig_len:,} -> {len(df):,} records ({orig_len - len(df):,} duplicates removed).")

    df = df.dropna(subset=[target_col] + FEATURE_NAMES)

    counts = df[target_col].value_counts().to_dict()
    print(f"Class distribution: Legitimate (0) = {counts.get(0, 0):,}, Phishing (1) = {counts.get(1, 0):,}")

    X = df[FEATURE_NAMES]
    y = df[target_col].astype(int)
    urls = df['url']

    return X, y, urls, counts


def plot_confusion_matrix(cm, labels, save_path):
    plt.figure(figsize=(6, 5))
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title('Honest Held-Out Confusion Matrix', fontsize=12, fontweight='bold', pad=12)
    plt.colorbar(fraction=0.046, pad=0.04)
    tick_marks = np.arange(len(labels))
    plt.xticks(tick_marks, labels, fontsize=10)
    plt.yticks(tick_marks, labels, fontsize=10)

    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, f"{cm[i, j]:,}",
                     horizontalalignment="center",
                     verticalalignment="center",
                     color="white" if cm[i, j] > thresh else "black",
                     fontsize=11, fontweight='bold')

    plt.ylabel('True Class', fontsize=11)
    plt.xlabel('Predicted Class', fontsize=11)
    plt.tight_layout()
    plt.savefig(save_path, dpi=200)
    plt.close()
    print(f"Confusion matrix plot saved to: {save_path}")


def plot_feature_importance(importances, feature_names, save_path, top_n=20):
    sorted_idx = np.argsort(importances)[-top_n:]
    plt.figure(figsize=(10, 8))
    plt.barh(range(top_n), importances[sorted_idx], align='center', color='#1A73E8')
    plt.yticks(range(top_n), [feature_names[i] for i in sorted_idx], fontsize=9)
    plt.xlabel('Relative Feature Importance (Gini / Gain)', fontsize=11)
    plt.title(f'Top {top_n} Deterministic URL Lexical Features', fontsize=12, fontweight='bold', pad=12)
    plt.tight_layout()
    plt.savefig(save_path, dpi=200)
    plt.close()
    print(f"Feature importance plot saved to: {save_path}")


def plot_model_comparison(comparison_df, save_path):
    plt.figure(figsize=(9, 5))
    x = np.arange(len(comparison_df))
    width = 0.2

    plt.bar(x - 1.5*width, comparison_df['Accuracy'] * 100, width, label='Accuracy (%)', color='#1A73E8')
    plt.bar(x - 0.5*width, comparison_df['Precision'] * 100, width, label='Precision (%)', color='#34A853')
    plt.bar(x + 0.5*width, comparison_df['Recall'] * 100, width, label='Recall (%)', color='#FBBC04')
    plt.bar(x + 1.5*width, comparison_df['F1'] * 100, width, label='F1-Score (%)', color='#EA4335')

    plt.ylabel('Score (%)', fontsize=11)
    plt.title('Candidate Model Evaluation Benchmark', fontsize=12, fontweight='bold', pad=12)
    plt.xticks(x, comparison_df['Model'], fontsize=10)
    plt.ylim([85, 100])
    plt.legend(loc='lower right')
    plt.grid(axis='y', linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(save_path, dpi=200)
    plt.close()
    print(f"Model comparison plot saved to: {save_path}")


def main():
    args = parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    os.makedirs("documentation", exist_ok=True)

    print("=" * 70)
    print("PHISHGUARD AI - PRODUCTION MODEL TRAINING PIPELINE")
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Random Seed: {args.random_seed} | Test Fraction: {args.test_size}")
    print("=" * 70)

    X, y, urls, class_counts = load_and_preprocess_data(
        args.dataset, max_records=args.max_records, random_seed=args.random_seed
    )

    print(f"\nPartitioning dataset with stratified split (test_size={args.test_size})...")
    X_train, X_test, y_train, y_test, urls_train, urls_test = train_test_split(
        X, y, urls, test_size=args.test_size, random_state=args.random_seed, stratify=y
    )
    print(f"Train partition: {len(X_train):,} samples")
    print(f"Test partition:  {len(X_test):,} samples")

    candidates = {
        "Logistic Regression": Pipeline([
            ('scaler', StandardScaler()),
            ('clf', LogisticRegression(max_iter=500, random_state=args.random_seed))
        ]),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=200, learning_rate=0.1, max_leaf_nodes=31, random_state=args.random_seed
        ),
        "XGBoost Classifier": xgb.XGBClassifier(
            n_estimators=250,
            max_depth=9,
            learning_rate=0.1,
            subsample=0.85,
            colsample_bytree=0.85,
            random_state=args.random_seed,
            n_jobs=-1,
            eval_metric='logloss',
            tree_method='hist'
        )
    }

    results = []
    trained_models = {}

    for name, model in candidates.items():
        print(f"\nTraining candidate: {name} ...")
        t_start = time.time()
        model.fit(X_train, y_train)
        fit_time = time.time() - t_start

        t_eval = time.time()
        y_pred = model.predict(X_test)
        eval_time = (time.time() - t_eval) / len(X_test) * 1000

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test)[:, 1]
            roc_auc = roc_auc_score(y_test, y_prob)
        else:
            roc_auc = 0.0

        print(f"{name} Results:")
        print(f"    Train Time:   {fit_time:.2f}s | Latency: {eval_time:.4f} ms/sample")
        print(f"    Accuracy:     {acc * 100:.2f}%")
        print(f"    Precision:    {prec * 100:.2f}%")
        print(f"    Recall:       {rec * 100:.2f}%")
        print(f"    F1-Score:     {f1 * 100:.2f}%")
        print(f"    ROC-AUC:      {roc_auc:.4f}")

        results.append({
            "Model": name,
            "Accuracy": float(acc),
            "Precision": float(prec),
            "Recall": float(rec),
            "F1": float(f1),
            "ROC_AUC": float(roc_auc),
            "Fit_Time_s": float(fit_time),
            "Latency_ms": float(eval_time)
        })
        trained_models[name] = model

    results_df = pd.DataFrame(results)
    print("\n" + "=" * 70)
    print("MODEL COMPARISON SUMMARY")
    print(results_df.to_string(index=False))
    print("=" * 70)

    best_row = results_df.sort_values(by=["F1", "Accuracy"], ascending=False).iloc[0]
    best_name = best_row["Model"]
    best_model = trained_models[best_name]
    print(f"\nBEST MODEL SELECTED: {best_name} (Accuracy: {best_row['Accuracy']*100:.2f}%, F1: {best_row['F1']*100:.2f}%)")

    final_pred = best_model.predict(X_test)
    cm = confusion_matrix(y_test, final_pred)
    tn, fp, fn, tp = cm.ravel()
    report_dict = classification_report(y_test, final_pred, target_names=["Legitimate", "Phishing"], output_dict=True)

    print(f"\nHeld-Out Test Confusion Matrix:")
    print(f"    True Negative (Legitimate Correct): {tn:,}")
    print(f"    False Positive (False Alarm):       {fp:,}")
    print(f"    False Negative (Missed Phish):      {fn:,}")
    print(f"    True Positive (Phish Detected):     {tp:,}")

    best_model_path = os.path.join(args.output_dir, "best_model.joblib")
    joblib.dump(best_model, best_model_path, compress=3)
    print(f"Saved model artifact to: {best_model_path}")

    feature_names_path = os.path.join(args.output_dir, "feature_names.json")
    with open(feature_names_path, "w") as f:
        json.dump(FEATURE_NAMES, f, indent=2)

    training_metrics = {
        "best_model_name": best_name,
        "evaluation_metrics": {
            "accuracy": float(best_row["Accuracy"]),
            "precision": float(best_row["Precision"]),
            "recall": float(best_row["Recall"]),
            "f1_score": float(best_row["F1"]),
            "roc_auc": float(best_row["ROC_AUC"]),
            "confusion_matrix": {
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp)
            }
        },
        "candidate_comparisons": results,
        "dataset_statistics": {
            "source": args.dataset,
            "total_records": len(X),
            "train_records": len(X_train),
            "test_records": len(X_test),
            "class_counts": {str(k): int(v) for k, v in class_counts.items()}
        },
        "metadata": {
            "feature_count": len(FEATURE_NAMES),
            "approach": "Approach A (Deterministic URL-Only Lexical Features)",
            "leakage_free": True,
            "random_seed": args.random_seed,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "python_version": sys.version.split()[0]
        }
    }

    metrics_path = os.path.join(args.output_dir, "training_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(training_metrics, f, indent=2)

    report_path = os.path.join(args.output_dir, "classification_report.json")
    with open(report_path, "w") as f:
        json.dump(report_dict, f, indent=2)

    cm_plot_path = os.path.join(args.output_dir, "confusion_matrix.png")
    plot_confusion_matrix(cm, ["Legitimate", "Phishing"], cm_plot_path)

    comparison_plot_path = os.path.join(args.output_dir, "model_comparison.png")
    plot_model_comparison(results_df, comparison_plot_path)

    if hasattr(best_model, "feature_importances_"):
        fi_plot_path = os.path.join(args.output_dir, "feature_importance.png")
        plot_feature_importance(best_model.feature_importances_, FEATURE_NAMES, fi_plot_path)

    summary_md_path = os.path.join("documentation", "training_summary.md")
    summary_lines = [
        f"# Model Training & Evaluation Summary - PhishGuard AI\n",
        f"- Trained Model: `{best_name}`\n",
        f"- Training Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n",
        f"- Dataset: `{args.dataset}` ({len(X):,} deduplicated samples)\n",
        f"- Held-Out Test Set Size: {len(X_test):,} samples (20% stratified)\n",
        f"- Features Extracted: {len(FEATURE_NAMES)} deterministic URL-only lexical features\n\n",
        f"## Measured Test Metrics\n\n",
        f"- Test Accuracy: **{best_row['Accuracy']*100:.2f}%**\n",
        f"- Test Precision (Phishing): **{best_row['Precision']*100:.2f}%**\n",
        f"- Test Recall (Phishing): **{best_row['Recall']*100:.2f}%**\n",
        f"- Test F1-Score (Phishing): **{best_row['F1']*100:.2f}%**\n",
        f"- ROC-AUC Score: **{best_row['ROC_AUC']:.4f}**\n\n",
        f"## Confusion Matrix Breakdown\n\n",
        f"- True Negatives (Legitimate Correct): {tn:,}\n",
        f"- False Positives (Benign Flagged as Phishing): {fp:,}\n",
        f"- False Negatives (Phishing Missed): {fn:,}\n",
        f"- True Positives (Phishing Correctly Blocked): {tp:,}\n\n",
        f"## Candidate Model Comparison\n\n",
        f"| Model | Accuracy | Precision | Recall | F1-Score | Fit Time (s) | Latency (ms/sample) |\n",
        f"|---|---|---|---|---|---|---|\n"
    ]
    with open(summary_md_path, "w") as f:
        f.writelines(summary_lines)
        for r in results:
            f.write(f"| {r['Model']} | {r['Accuracy']*100:.2f}% | {r['Precision']*100:.2f}% | {r['Recall']*100:.2f}% | {r['F1']*100:.2f}% | {r['Fit_Time_s']:.2f}s | {r['Latency_ms']:.4f} ms |\n")

    print(f"Training summary saved to: {summary_md_path}")
    print("Training pipeline complete.")


if __name__ == "__main__":
    main()
