"""
train_model.py
--------------
ML Engineer - SIH 2026 (PS 26160)

Purpose:
    Reads features.csv, trains a Random Forest and XGBoost classifier,
    evaluates both, saves the best one as traffic_classifier.pkl
    
Usage:
    python train_model.py
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os

# ── 1. Load data ──────────────────────────────────────────────────────────────
print("Loading features.csv ...")
df = pd.read_csv('features.csv')
print(f"Total rows: {len(df)}")
print(f"Classes: {df['label'].unique()}")
print(f"Class distribution:\n{df.groupby('label').size()}\n")

# ── 2. Prepare X (features) and y (labels) ────────────────────────────────────
feature_cols = [
    'packet_count', 'total_bytes', 'duration_sec', 'bytes_per_sec',
    'mean_size', 'std_size', 'min_size', 'max_size',
    'mean_inter_arrival', 'std_inter_arrival',
    'fwd_packet_ratio', 'bwd_packet_ratio'
]

X = df[feature_cols]
y = df['label']

# Encode text labels to numbers (Random Forest needs numbers)
le = LabelEncoder()
y_encoded = le.fit_transform(y)
print(f"Label mapping: {dict(zip(le.classes_, le.transform(le.classes_)))}\n")

# ── 3. Train/test split ───────────────────────────────────────────────────────
# 80% training, 20% testing
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)
print(f"Training rows: {len(X_train)}, Testing rows: {len(X_test)}\n")

# ── 4. Train Random Forest ────────────────────────────────────────────────────
print("Training Random Forest ...")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)
rf_preds = rf_model.predict(X_test)
rf_score = rf_model.score(X_test, y_test)
print(f"Random Forest Accuracy: {rf_score:.2%}")
print("\nRandom Forest Classification Report:")
print(classification_report(y_test, rf_preds, target_names=le.classes_))

# ── 5. Train XGBoost ─────────────────────────────────────────────────────────
print("Training XGBoost ...")
xgb_model = xgb.XGBClassifier(
    n_estimators=100,
    random_state=42,
    eval_metric='mlogloss',
    verbosity=0
)
xgb_model.fit(X_train, y_train)
xgb_preds = xgb_model.predict(X_test)
xgb_score = xgb_model.score(X_test, y_test)
print(f"XGBoost Accuracy: {xgb_score:.2%}")
print("\nXGBoost Classification Report:")
print(classification_report(y_test, xgb_preds, target_names=le.classes_))

# ── 6. Pick the best model ────────────────────────────────────────────────────
if rf_score >= xgb_score:
    best_model = rf_model
    best_name = "Random Forest"
    best_preds = rf_preds
else:
    best_model = xgb_model
    best_name = "XGBoost"
    best_preds = xgb_preds

print(f"\nBest model: {best_name} ({max(rf_score, xgb_score):.2%} accuracy)")

# ── 7. Confusion matrix ───────────────────────────────────────────────────────
print("\nGenerating confusion matrix ...")
cm = confusion_matrix(y_test, best_preds)
plt.figure(figsize=(8, 6))
sns.heatmap(
    cm,
    annot=True,
    fmt='d',
    xticklabels=le.classes_,
    yticklabels=le.classes_,
    cmap='Blues'
)
plt.title(f'Confusion Matrix - {best_name}')
plt.ylabel('Actual')
plt.xlabel('Predicted')
plt.tight_layout()
plt.savefig('confusion_matrix.png')
print("Confusion matrix saved as confusion_matrix.png")

# ── 8. Save the model ─────────────────────────────────────────────────────────
os.makedirs('models', exist_ok=True)
joblib.dump(best_model, 'models/traffic_classifier.pkl')
joblib.dump(le, 'models/label_encoder.pkl')
print(f"\nModel saved to models/traffic_classifier.pkl")
print(f"Label encoder saved to models/label_encoder.pkl")
print("\nDone! Your model is ready.")