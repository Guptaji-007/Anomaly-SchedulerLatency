"""
ML Model Training and Cause Classification
Trains models for:
1. Anomaly Detection (Isolation Forest)
2. Cause Classification (Random Forest, XGBoost)
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import json
import pickle
from datetime import datetime

from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score, 
    precision_recall_fscore_support, roc_auc_score, roc_curve,
    auc, precision_recall_curve
)
from sklearn.svm import OneClassSVM
import matplotlib.pyplot as plt
import seaborn as sns

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False


class AnomalyDetector:
    """One-class anomaly detector using Isolation Forest"""
    
    def __init__(self, contamination: float = 0.1):
        """
        Initialize anomaly detector
        
        Args:
            contamination: Expected fraction of anomalies in training data
        """
        self.contamination = contamination
        self.model = None
        self.scaler = None
        self.features = None
        self.threshold = None
        self.stats = {}
        
    def train(self, X: pd.DataFrame, y: pd.Series = None) -> Dict:
        """
        Train anomaly detection model
        
        Args:
            X: Feature DataFrame
            y: Optional labels for calibration
            
        Returns:
            Training statistics
        """
        print(f"\n[Anomaly Detector] Training on {len(X)} samples...")
        
        # Scale features
        self.scaler = RobustScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.features = X.columns.tolist()
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
            n_jobs=-1
        )
        
        predictions = self.model.fit_predict(X_scaled)
        anomaly_scores = self.model.score_samples(X_scaled)
        
        # Calculate statistics
        n_anomalies = np.sum(predictions == -1)
        n_normal = np.sum(predictions == 1)
        
        self.stats = {
            'n_training_samples': len(X),
            'n_detected_anomalies': n_anomalies,
            'n_normal': n_normal,
            'anomaly_percentage': 100 * n_anomalies / len(X),
            'anomaly_scores_mean': float(np.mean(anomaly_scores)),
            'anomaly_scores_std': float(np.std(anomaly_scores)),
            'anomaly_scores_min': float(np.min(anomaly_scores)),
            'anomaly_scores_max': float(np.max(anomaly_scores)),
        }
        
        print(f"  Detected {n_anomalies} anomalies ({self.stats['anomaly_percentage']:.2f}%)")
        print(f"  Anomaly scores range: [{self.stats['anomaly_scores_min']:.4f}, {self.stats['anomaly_scores_max']:.4f}]")
        
        return self.stats
    
    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies
        
        Returns:
            predictions: -1 for anomaly, 1 for normal
            scores: anomaly scores (lower = more anomalous)
        """
        if self.model is None:
            raise RuntimeError("Model not trained yet")
        
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)
        
        return predictions, scores
    
    def get_anomaly_indices(self, X: pd.DataFrame) -> np.ndarray:
        """Get indices of detected anomalies"""
        predictions, _ = self.predict(X)
        return np.where(predictions == -1)[0]
    
    def save(self, path: str):
        """Save model to disk"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'features': self.features,
            'stats': self.stats,
        }
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)
        print(f"Anomaly detector saved to {path}")
    
    def load(self, path: str):
        """Load model from disk"""
        with open(path, 'rb') as f:
            model_data = pickle.load(f)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.features = model_data['features']
        self.stats = model_data['stats']
        print(f"Anomaly detector loaded from {path}")


class CauseClassifier:
    """Multi-class classifier for workload cause identification"""
    
    def __init__(self, model_type: str = 'random_forest'):
        """
        Initialize classifier
        
        Args:
            model_type: 'random_forest', 'gradient_boosting', or 'xgboost'
        """
        self.model_type = model_type
        self.model = None
        self.scaler = None
        self.features = None
        self.classes = None
        self.feature_importance = None
        self.stats = {}
        
    def train(self, X: pd.DataFrame, y: pd.Series, 
              validation_split: float = 0.2,
              hyperparameter_tuning: bool = False) -> Dict:
        """
        Train cause classification model
        
        Args:
            X: Feature DataFrame
            y: Target labels
            validation_split: Fraction for validation
            hyperparameter_tuning: Whether to perform grid search
            
        Returns:
            Training statistics
        """
        print(f"\n[Cause Classifier] Training {self.model_type} on {len(X)} samples...")
        print(f"  Classes: {sorted(y.unique())}")
        
        # Scale features
        self.scaler = RobustScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.features = X.columns.tolist()
        self.classes = np.sort(y.unique())
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X_scaled, y, test_size=validation_split, 
            random_state=42, stratify=y
        )
        
        if hyperparameter_tuning:
            self._tune_hyperparameters(X_train, y_train)
        else:
            self._create_model()
        
        # Train model
        self.model.fit(X_train, y_train)
        
        # Evaluate
        train_pred = self.model.predict(X_train)
        val_pred = self.model.predict(X_val)
        
        train_acc = accuracy_score(y_train, train_pred)
        val_acc = accuracy_score(y_val, val_pred)
        
        # Feature importance
        if hasattr(self.model, 'feature_importances_'):
            self.feature_importance = pd.DataFrame({
                'feature': self.features,
                'importance': self.model.feature_importances_
            }).sort_values('importance', ascending=False)
        
        self.stats = {
            'model_type': self.model_type,
            'n_training_samples': len(X),
            'n_validation_samples': len(X_val),
            'n_classes': len(self.classes),
            'train_accuracy': float(train_acc),
            'validation_accuracy': float(val_acc),
            # NOTE: raw prediction arrays intentionally excluded from stats so
            # save_pipeline_config() (json.dump) and pickle both stay clean.
        }
        
        print(f"  Train accuracy: {train_acc:.4f}")
        print(f"  Validation accuracy: {val_acc:.4f}")
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_scaled, y, cv=5)
        self.stats['cv_mean'] = float(cv_scores.mean())
        self.stats['cv_std'] = float(cv_scores.std())
        print(f"  5-fold CV: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        return self.stats
    
    def _create_model(self):
        """Create model based on model_type"""
        if self.model_type == 'random_forest':
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            )
        elif self.model_type == 'gradient_boosting':
            self.model = GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=7,
                min_samples_split=5,
                random_state=42
            )
        elif self.model_type == 'xgboost' and HAS_XGBOOST:
            self.model = xgb.XGBClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=7,
                random_state=42,
                use_label_encoder=False,
                eval_metric='logloss',
                n_jobs=-1
            )
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
    
    def _tune_hyperparameters(self, X_train: np.ndarray, y_train: pd.Series):
        """Perform hyperparameter tuning with GridSearchCV"""
        print("  Performing hyperparameter tuning...")
        
        if self.model_type == 'random_forest':
            param_grid = {
                'n_estimators': [50, 100],
                'max_depth': [10, 15, 20],
                'min_samples_split': [5, 10],
            }
            base_model = RandomForestClassifier(random_state=42, n_jobs=-1)
        elif self.model_type == 'gradient_boosting':
            param_grid = {
                'n_estimators': [50, 100],
                'learning_rate': [0.05, 0.1],
                'max_depth': [5, 7],
            }
            base_model = GradientBoostingClassifier(random_state=42)
        else:
            self._create_model()
            return
        
        grid_search = GridSearchCV(base_model, param_grid, cv=3, n_jobs=-1, verbose=1)
        grid_search.fit(X_train, y_train)
        
        self.model = grid_search.best_estimator_
        print(f"  Best parameters: {grid_search.best_params_}")
    
    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict cause class
        
        Returns:
            predictions: Predicted class labels
            probabilities: Class probabilities
        """
        if self.model is None:
            raise RuntimeError("Model not trained yet")
        
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        
        if hasattr(self.model, 'predict_proba'):
            probabilities = self.model.predict_proba(X_scaled)
        else:
            probabilities = None
        
        return predictions, probabilities
    
    def predict_with_confidence(self, X: pd.DataFrame) -> pd.DataFrame:
        """Predict with confidence scores"""
        predictions, probabilities = self.predict(X)
        
        if probabilities is not None:
            max_probs = np.max(probabilities, axis=1)
            result_df = pd.DataFrame({
                'predicted_class': predictions,
                'confidence': max_probs,
                'class_name': [self._label_to_name(p) for p in predictions]
            })
        else:
            result_df = pd.DataFrame({
                'predicted_class': predictions,
                'class_name': [self._label_to_name(p) for p in predictions]
            })
        
        return result_df
    
    def _label_to_name(self, label: int) -> str:
        """Convert label to workload name (inline mapping avoids import-path issues)."""
        _MAP = {
            0: 'baseline', 1: 'cpu_contention', 2: 'heavy_contention',
            3: 'disk_io', 4: 'memory_pressure', 5: 'lock_contention',
            6: 'ipc_communication', 7: 'context_switching', 8: 'mixed', 9: 'anomaly',
        }
        return _MAP.get(int(label), f'unknown_{label}')
    
    def get_feature_importance(self, top_n: int = 15) -> pd.DataFrame:
        """Get top N most important features"""
        if self.feature_importance is None:
            return None
        return self.feature_importance.head(top_n)
    
    def save(self, path: str):
        """Save model to disk"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'features': self.features,
            'classes': self.classes,
            'feature_importance': self.feature_importance,
            'stats': self.stats,
            'model_type': self.model_type,
        }
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)
        print(f"Cause classifier saved to {path}")
    
    def load(self, path: str):
        """Load model from disk"""
        with open(path, 'rb') as f:
            model_data = pickle.load(f)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.features = model_data['features']
        self.classes = model_data['classes']
        self.feature_importance = model_data['feature_importance']
        self.stats = model_data['stats']
        self.model_type = model_data['model_type']
        print(f"Cause classifier loaded from {path}")


class ModelEvaluator:
    """Generate evaluation reports and visualizations"""
    
    @staticmethod
    def evaluate_classifier(classifier: CauseClassifier, X_test: pd.DataFrame, 
                           y_test: pd.Series, output_dir: str = None) -> Dict:
        """
        Generate comprehensive evaluation report
        
        Returns:
            Dictionary with all evaluation metrics
        """
        predictions, probabilities = classifier.predict(X_test)
        
        # Metrics
        accuracy = accuracy_score(y_test, predictions)
        precision, recall, f1, support = precision_recall_fscore_support(y_test, predictions, average='weighted')
        
        report = classification_report(y_test, predictions, output_dict=True)
        conf_matrix = confusion_matrix(y_test, predictions)
        
        results = {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'classification_report': report,
            'confusion_matrix': conf_matrix.tolist(),
        }
        
        print("\n" + "="*60)
        print("CLASSIFIER EVALUATION")
        print("="*60)
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1-Score: {f1:.4f}")
        print("\nDetailed Classification Report:")
        print(classification_report(y_test, predictions))
        
        # Visualization
        if output_dir:
            Path(output_dir).mkdir(exist_ok=True)
            
            # Confusion matrix
            plt.figure(figsize=(10, 8))
            sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues')
            plt.title('Confusion Matrix')
            plt.xlabel('Predicted')
            plt.ylabel('Actual')
            plt.savefig(f'{output_dir}/confusion_matrix.png', dpi=100, bbox_inches='tight')
            plt.close()
            
            # Feature importance
            importance_df = classifier.get_feature_importance(top_n=15)
            if importance_df is not None:
                plt.figure(figsize=(10, 6))
                sns.barplot(data=importance_df, x='importance', y='feature')
                plt.title('Top 15 Feature Importance')
                plt.xlabel('Importance')
                plt.savefig(f'{output_dir}/feature_importance.png', dpi=100, bbox_inches='tight')
                plt.close()
        
        return results


if __name__ == "__main__":
    print("ML Model training module - import and use classes directly")