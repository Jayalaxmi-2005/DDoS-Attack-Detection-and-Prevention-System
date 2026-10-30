# -*- coding: utf-8 -*-
"""
setup.py - One-step model training script
==========================================
Run this ONCE before starting the app.
Generates synthetic training data and trains both ML models.

Usage:
    python setup.py
"""

import os
import sys
import time

BACKEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
sys.path.insert(0, BACKEND_DIR)

# Ensure data directories exist
os.makedirs(os.path.join("data", "logs"),     exist_ok=True)
os.makedirs(os.path.join("data", "training"), exist_ok=True)
os.makedirs(os.path.join("backend", "models"), exist_ok=True)

print("=" * 60)
print("DDoS Detection System - Setup & Model Training")
print("=" * 60)
print()

# ------- 1. Generate and save training data as CSV -------
print("[Step 1/3] Generating synthetic training dataset ...")
import pandas as pd
from simulator import generate_training_dataset

dataset = generate_training_dataset(n_samples=6000)
df = pd.DataFrame(dataset)
csv_path = os.path.join("data", "training", "synthetic_training_data.csv")
df.to_csv(csv_path, index=False)
print(f"  Saved {len(df)} rows to {csv_path}")
print(f"  Label distribution:\n{df['label'].value_counts().to_string()}")
print()

# ------- 2. Train supervised ML model -------
print("[Step 2/3] Training supervised Random Forest model ...")
t0 = time.time()
from ml_detector import train
result = train(n_samples=6000, save=True)
elapsed = time.time() - t0
print(f"  Training complete in {elapsed:.1f}s")
print(f"  Synthetic test accuracy: {result['accuracy']:.4f}")
print("  [NOTE] Accuracy is on synthetic data only - NOT real traffic.")
print()

# Print per-class report
report = result["report"]
print("  Per-class performance (synthetic test set):")
print(f"  {'Class':<15} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'Support':>10}")
print("  " + "-" * 55)
for cls, metrics in report.items():
    if isinstance(metrics, dict):
        print(f"  {cls:<15} {metrics['precision']:>10.3f} {metrics['recall']:>10.3f} {metrics['f1-score']:>10.3f} {int(metrics['support']):>10}")
print()

# ------- 3. Train anomaly detection model -------
print("[Step 3/3] Training Isolation Forest anomaly detector ...")
t0 = time.time()
from anomaly_detector import train_anomaly
train_anomaly(n_normal=4000, save=True)
elapsed = time.time() - t0
print(f"  Training complete in {elapsed:.1f}s")
print()

print("=" * 60)
print("Setup complete! Now run:")
print()
print("    python backend/app.py")
print()
print("Then open http://localhost:5000 in your browser.")
print("=" * 60)
