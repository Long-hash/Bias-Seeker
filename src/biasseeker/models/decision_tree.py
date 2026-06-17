from __future__ import annotations

from pathlib import Path
from typing import Any


def train_decision_tree(features_csv: Path) -> dict[str, Any]:
    try:
        import pandas as pd
        from sklearn.metrics import accuracy_score
        from sklearn.tree import DecisionTreeClassifier
    except ImportError as exc:  # pragma: no cover - depends on AutoDL environment
        raise RuntimeError("pandas and scikit-learn are required for Decision Tree training.") from exc

    data = pd.read_csv(features_csv)
    required = {"split", "label"}
    missing = required - set(data.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")
    feature_columns = [column for column in data.columns if column not in {"split", "label", "session_id"}]
    if not feature_columns:
        raise ValueError("No feature columns found.")

    train = data[data["split"] == "train"]
    test = data[data["split"] == "test"]
    if train.empty or test.empty:
        raise ValueError("Feature matrix must contain non-empty train and test splits.")

    classifier = DecisionTreeClassifier(random_state=2026)
    classifier.fit(train[feature_columns], train["label"])
    predictions = classifier.predict(test[feature_columns])
    return {
        "accuracy": float(accuracy_score(test["label"], predictions)),
        "train_rows": int(len(train)),
        "test_rows": int(len(test)),
        "feature_count": int(len(feature_columns)),
    }
