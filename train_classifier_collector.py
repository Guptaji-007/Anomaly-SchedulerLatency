#!/usr/bin/env python3
"""
===================================================================
TRAIN CLASSIFIER - Using Collector Aggregated Statistics
===================================================================
Trains ML model using window-based latency statistics from collector
Features: avg_lat, min_lat, max_lat, p95_lat, p99_lat, stddev_lat,
          switch_count, over20, over50, over100, avg_prio, highest_prio
"""

import pandas as pd
import numpy as np
import sys
import json
from pathlib import Path
from datetime import datetime
import joblib

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
import xgboost as xgb

class ClassifierTrainer:
    def __init__(self, dataset_path=None):
        self.script_dir = Path(__file__).parent.absolute()
        self.ebpf_dir = self.script_dir / "ebpf_logs"
        
        if dataset_path is None:
            self.dataset_path = self.ebpf_dir / "labeled_dataset.csv"
        else:
            self.dataset_path = Path(dataset_path)
        
        self.data = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.scaler = None
        self.encoder = None
        self.model = None
        self.feature_names = None
        self.model_name = "xgboost"
    
    def print_header(self, text):
        print(f"\n{'='*70}")
        print(f"{text:^70}")
        print(f"{'='*70}\n")
    
    def print_step(self, num, text):
        print(f"[STEP {num}] {text}")
    
    def print_success(self, text):
        print(f"✓ {text}")
    
    def print_error(self, text):
        print(f"✗ {text}")
    
    # ===================================================================
    # STEP 1: LOAD DATASET
    # ===================================================================
    
    def load_dataset(self):
        """Load labeled dataset"""
        self.print_step("1", "Loading dataset...")
        
        if not self.dataset_path.exists():
            self.print_error(f"Dataset not found: {self.dataset_path}")
            print("\nGenerate it first with:")
            print("  python3 generate_labeled_dataset.py\n")
            return False
        
        try:
            self.data = pd.read_csv(self.dataset_path)
            
            print(f"  File: {self.dataset_path}")
            print(f"  Windows: {len(self.data)}")
            print(f"  Columns: {list(self.data.columns)}")
            
            if 'label' not in self.data.columns:
                self.print_error("Dataset missing 'label' column")
                return False
            
            print(f"\nClass distribution:")
            dist = self.data['label'].value_counts()
            for label, count in sorted(dist.items()):
                pct = 100 * count / len(self.data)
                print(f"  {label:30s} {count:4d} ({pct:5.1f}%)")
            
            self.print_success("Dataset loaded")
            return True
            
        except Exception as e:
            self.print_error(f"Failed to load dataset: {e}")
            return False
    
    # ===================================================================
    # STEP 2: PREPARE FEATURES
    # ===================================================================
    
    def prepare_features(self):
        """Extract features from collector data"""
        self.print_step("2", "Preparing features...")
        
        # Features from collector statistics
        feature_cols = [
            'avg_lat', 'min_lat', 'max_lat', 'p95_lat', 'p99_lat', 'stddev_lat',
            'switch_count', 'over20', 'over50', 'over100', 'avg_prio', 'highest_prio'
        ]
        
        # Check which features exist
        available_features = [col for col in feature_cols if col in self.data.columns]
        
        print(f"  Available features: {len(available_features)}")
        for feat in available_features:
            print(f"    • {feat}")
        
        if len(available_features) < 6:
            self.print_error(f"Not enough features. Expected 12, got {len(available_features)}")
            return None, None
        
        self.feature_names = available_features
        
        # Extract features
        X = self.data[available_features].values
        
        # Handle missing values
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        
        # Target
        y = self.data['label'].values
        
        print(f"\n  Feature matrix: {X.shape}")
        print(f"  Target shape: {y.shape}")
        print(f"  Classes: {len(np.unique(y))}")
        
        self.print_success("Features prepared")
        
        return X, y
    
    # ===================================================================
    # STEP 3: SPLIT AND SCALE
    # ===================================================================
    
    def prepare_data(self):
        """Split and scale data"""
        self.print_step("3", "Splitting and scaling data...")
        
        X, y = self.prepare_features()
        if X is None:
            return False
        
        # Encode labels
        self.encoder = LabelEncoder()
        y_encoded = self.encoder.fit_transform(y)
        
        print(f"  Label encoding:")
        for i, label in enumerate(self.encoder.classes_):
            print(f"    {label:30s} → {i}")
        
        # Split data
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        
        print(f"\n  Train set: {len(self.X_train)} windows")
        print(f"  Test set: {len(self.X_test)} windows")
        
        # Scale features
        self.scaler = StandardScaler()
        self.X_train = self.scaler.fit_transform(self.X_train)
        self.X_test = self.scaler.transform(self.X_test)
        
        print(f"\n  Features scaled (mean=0, std=1)")
        
        self.print_success("Data prepared")
        return True
    
    # ===================================================================
    # STEP 4: TRAIN MODELS
    # ===================================================================
    
    def train_models(self):
        """Train and compare models"""
        self.print_step("4", "Training models...")
        
        models = {
            'xgboost': xgb.XGBClassifier(
                n_estimators=100, max_depth=6, learning_rate=0.1,
                subsample=0.8, random_state=42, verbose=0
            ),
            'random_forest': RandomForestClassifier(
                n_estimators=100, max_depth=10, random_state=42, n_jobs=-1
            ),
            'logistic_regression': LogisticRegression(
                max_iter=1000, multi_class='multinomial', random_state=42, n_jobs=-1
            )
        }
        
        results = {}
        
        for name, model in models.items():
            print(f"\n  Training {name}...", end=" ", flush=True)
            
            model.fit(self.X_train, self.y_train)
            
            train_score = model.score(self.X_train, self.y_train)
            test_score = model.score(self.X_test, self.y_test)
            cv_scores = cross_val_score(model, self.X_train, self.y_train, cv=5)
            
            results[name] = {
                'model': model,
                'train_accuracy': train_score,
                'test_accuracy': test_score,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std()
            }
            
            print(f"✓")
            print(f"    Train: {train_score:.1%} | Test: {test_score:.1%} | CV: {cv_scores.mean():.1%}±{cv_scores.std():.1%}")
        
        # Select best
        best_name = max(results.keys(), key=lambda x: results[x]['test_accuracy'])
        self.model = results[best_name]['model']
        self.model_name = best_name
        
        print(f"\n  ✓ Selected: {best_name.upper()}")
        
        return results[best_name]
    
    # ===================================================================
    # STEP 5: EVALUATE
    # ===================================================================
    
    def evaluate(self, best_result):
        """Evaluate model performance"""
        self.print_step("5", "Evaluating model...")
        
        from sklearn.metrics import classification_report, confusion_matrix
        
        y_pred = self.model.predict(self.X_test)
        report = classification_report(self.y_test, y_pred,
                                      target_names=self.encoder.classes_,
                                      output_dict=True)
        
        print(f"\nPer-class performance:")
        print(f"{'Class':30s} {'Precision':>12s} {'Recall':>12s} {'F1':>12s}")
        print(f"{'-'*70}")
        
        for label in self.encoder.classes_:
            if label in report:
                p = report[label]['precision']
                r = report[label]['recall']
                f1 = report[label]['f1-score']
                print(f"{label:30s} {p:12.1%} {r:12.1%} {f1:12.1%}")
        
        print(f"\nOverall:")
        print(f"  Accuracy:  {best_result['test_accuracy']:.1%}")
        print(f"  Precision: {report['weighted avg']['precision']:.1%}")
        print(f"  Recall:    {report['weighted avg']['recall']:.1%}")
        print(f"  F1-Score:  {report['weighted avg']['f1-score']:.1%}")
        
        self.print_success("Evaluation complete")
        
        return report
    
    # ===================================================================
    # STEP 6: SAVE MODEL
    # ===================================================================
    
    def save_model(self, best_result, report):
        """Save trained model"""
        self.print_step("6", "Saving model...")
        
        # Save model
        model_path = self.ebpf_dir / "collector_classifier.pkl"
        joblib.dump(self.model, model_path)
        print(f"  Model: {model_path}")
        
        # Save scaler
        scaler_path = self.ebpf_dir / "collector_scaler.pkl"
        joblib.dump(self.scaler, scaler_path)
        print(f"  Scaler: {scaler_path}")
        
        # Save encoder
        encoder_path = self.ebpf_dir / "collector_encoder.pkl"
        joblib.dump(self.encoder, encoder_path)
        print(f"  Encoder: {encoder_path}")
        
        # Save metadata
        metadata = {
            'model_type': self.model_name,
            'trained_at': datetime.now().isoformat(),
            'dataset': str(self.dataset_path),
            'windows': len(self.data),
            'features': self.feature_names,
            'classes': list(self.encoder.classes_),
            'train_accuracy': float(best_result['train_accuracy']),
            'test_accuracy': float(best_result['test_accuracy']),
            'cv_score': float(best_result['cv_mean']),
            'cv_std': float(best_result['cv_std']),
            'per_class_performance': {}
        }
        
        for label in self.encoder.classes_:
            if label in report:
                metadata['per_class_performance'][label] = {
                    'precision': float(report[label]['precision']),
                    'recall': float(report[label]['recall']),
                    'f1_score': float(report[label]['f1-score'])
                }
        
        metadata_path = self.ebpf_dir / "collector_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"  Metadata: {metadata_path}")
        
        self.print_success("Model saved")
        
        return {
            'model_path': str(model_path),
            'scaler_path': str(scaler_path),
            'encoder_path': str(encoder_path),
            'metadata_path': str(metadata_path)
        }
    
    # ===================================================================
    # MAIN
    # ===================================================================
    
    def train(self):
        """Complete training"""
        self.print_header("TRAINING WORKLOAD CLASSIFIER")
        
        if not self.load_dataset():
            return False
        
        if not self.prepare_data():
            return False
        
        best_result = self.train_models()
        report = self.evaluate(best_result)
        paths = self.save_model(best_result, report)
        
        self.print_header("✓ TRAINING COMPLETE")
        
        print("Saved files:")
        for key, path in paths.items():
            print(f"  • {path}")
        
        print(f"\nPerformance:")
        print(f"  Test Accuracy: {best_result['test_accuracy']:.1%}")
        print(f"  CV Score: {best_result['cv_mean']:.1%}±{best_result['cv_std']:.1%}")
        
        print(f"\nNext:")
        print(f"  python3 explain_workload.py")
        
        return True

if __name__ == "__main__":
    try:
        trainer = ClassifierTrainer()
        success = trainer.train()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Error: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
