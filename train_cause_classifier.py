#!/usr/bin/env python3
"""
===================================================================
TRAIN CAUSE CLASSIFIER - XGBoost Model Training
===================================================================
Trains ML model to classify latency spike causes from labeled dataset
"""

import pandas as pd
import numpy as np
import sys
import json
from pathlib import Path
from datetime import datetime
import joblib

# ML imports
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
import xgboost as xgb

class SpikeClassifierTrainer:
    def __init__(self, dataset_path=None):
        """Initialize trainer"""
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
        self.model_name = "xgboost"
    
    def print_header(self, text):
        print(f"\n{'='*60}")
        print(f"{text:^60}")
        print(f"{'='*60}\n")
    
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
        """Load labeled dataset from CSV"""
        self.print_step("1", "Loading dataset...")
        
        if not self.dataset_path.exists():
            self.print_error(f"Dataset not found: {self.dataset_path}")
            print("\nGenerate it first with:")
            print("  python3 run_on_linux.py")
            return False
        
        try:
            self.data = pd.read_csv(self.dataset_path)
            print(f"  File: {self.dataset_path}")
            print(f"  Samples: {len(self.data)}")
            print(f"  Columns: {list(self.data.columns)}")
            
            # Check for required columns
            if 'latency_us' not in self.data.columns or 'workload_cause' not in self.data.columns:
                self.print_error("Dataset missing required columns (latency_us, workload_cause)")
                return False
            
            # Show class distribution
            print(f"\nClass distribution:")
            dist = self.data['workload_cause'].value_counts()
            for cause, count in dist.items():
                pct = 100 * count / len(self.data)
                print(f"  {cause:30s} {count:6d} ({pct:5.1f}%)")
            
            self.print_success("Dataset loaded")
            return True
            
        except Exception as e:
            self.print_error(f"Failed to load dataset: {e}")
            return False
    
    # ===================================================================
    # STEP 2: FEATURE ENGINEERING
    # ===================================================================
    
    def create_features(self):
        """Extract features from latency data"""
        self.print_step("2", "Creating features...")
        
        # Basic feature: latency value itself
        X = self.data[['latency_us']].values
        
        # Advanced features
        print("  Extracting features:")
        features = []
        
        # Feature 1: Raw latency
        print(f"    • Raw latency")
        features.append(self.data['latency_us'].values)
        
        # Feature 2: Log latency (handles scale)
        print(f"    • Log latency")
        features.append(np.log1p(self.data['latency_us'].values))
        
        # Feature 3: Squared latency (emphasizes high values)
        print(f"    • Squared latency")
        features.append((self.data['latency_us'].values ** 2) / 1e6)
        
        # Feature 4: Latency bins (categorization)
        print(f"    • Latency bins")
        bins = pd.cut(self.data['latency_us'], bins=5).cat.codes.values
        features.append(bins.astype(float))
        
        # Feature 5: Normalized latency (0-1 scale)
        print(f"    • Normalized latency")
        normalized = (self.data['latency_us'] - self.data['latency_us'].min()) / \
                     (self.data['latency_us'].max() - self.data['latency_us'].min())
        features.append(normalized.values)
        
        # Combine features
        X = np.column_stack(features)
        
        # Target: workload cause labels
        y = self.data['workload_cause'].values
        
        print(f"\n  Feature matrix shape: {X.shape}")
        print(f"  Target shape: {y.shape}")
        print(f"  Unique classes: {len(np.unique(y))}")
        
        self.print_success("Features created")
        
        return X, y
    
    # ===================================================================
    # STEP 3: PREPARE DATA
    # ===================================================================
    
    def prepare_data(self):
        """Split data and scale features"""
        self.print_step("3", "Preparing data...")
        
        X, y = self.create_features()
        
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
        
        print(f"\n  Train set: {len(self.X_train)} samples")
        print(f"  Test set: {len(self.X_test)} samples")
        
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
        """Train multiple models and select best"""
        self.print_step("4", "Training models...")
        
        models_to_try = {
            'xgboost': xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                random_state=42,
                verbose=0
            ),
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            ),
            'logistic_regression': LogisticRegression(
                max_iter=1000,
                multi_class='multinomial',
                random_state=42,
                n_jobs=-1
            )
        }
        
        results = {}
        
        for name, model in models_to_try.items():
            print(f"\n  Training {name}...", end=" ", flush=True)
            
            # Train
            model.fit(self.X_train, self.y_train)
            
            # Evaluate
            train_score = model.score(self.X_train, self.y_train)
            test_score = model.score(self.X_test, self.y_test)
            
            # Cross-validation
            cv_scores = cross_val_score(model, self.X_train, self.y_train, cv=5)
            
            results[name] = {
                'model': model,
                'train_accuracy': train_score,
                'test_accuracy': test_score,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std()
            }
            
            print(f"✓")
            print(f"    Train acc: {train_score:.1%}")
            print(f"    Test acc:  {test_score:.1%}")
            print(f"    CV score:  {cv_scores.mean():.1%} ± {cv_scores.std():.1%}")
        
        # Select best model
        print(f"\n  Selecting best model (by test accuracy)...")
        best_model_name = max(results.keys(), 
                             key=lambda x: results[x]['test_accuracy'])
        
        self.model = results[best_model_name]['model']
        self.model_name = best_model_name
        best_result = results[best_model_name]
        
        print(f"\n  ✓ Selected: {best_model_name.upper()}")
        print(f"    Test accuracy: {best_result['test_accuracy']:.1%}")
        
        return best_result
    
    # ===================================================================
    # STEP 5: EVALUATE MODEL
    # ===================================================================
    
    def evaluate_model(self, best_result):
        """Detailed model evaluation"""
        self.print_step("5", "Evaluating model...")
        
        from sklearn.metrics import classification_report, confusion_matrix
        
        # Predictions
        y_pred = self.model.predict(self.X_test)
        
        # Classification report
        report = classification_report(self.y_test, y_pred, 
                                      target_names=self.encoder.classes_,
                                      output_dict=True)
        
        print(f"\nPer-class performance:")
        print(f"{'Class':30s} {'Precision':>10s} {'Recall':>10s} {'F1':>10s}")
        print(f"{'-'*60}")
        
        for label in self.encoder.classes_:
            if label in report:
                p = report[label]['precision']
                r = report[label]['recall']
                f1 = report[label]['f1-score']
                print(f"{label:30s} {p:10.2%} {r:10.2%} {f1:10.2%}")
        
        # Overall metrics
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
        """Save trained model and components"""
        self.print_step("6", "Saving model...")
        
        # Save model
        model_path = self.ebpf_dir / "cause_classifier_xgboost.pkl"
        joblib.dump(self.model, model_path)
        print(f"  Model saved: {model_path}")
        
        # Save scaler
        scaler_path = self.ebpf_dir / "cause_scaler.pkl"
        joblib.dump(self.scaler, scaler_path)
        print(f"  Scaler saved: {scaler_path}")
        
        # Save encoder
        encoder_path = self.ebpf_dir / "cause_encoder.pkl"
        joblib.dump(self.encoder, encoder_path)
        print(f"  Encoder saved: {encoder_path}")
        
        # Save metadata
        metadata = {
            'model_type': self.model_name,
            'trained_at': datetime.now().isoformat(),
            'dataset': str(self.dataset_path),
            'samples': len(self.data),
            'classes': list(self.encoder.classes_),
            'train_accuracy': float(best_result['train_accuracy']),
            'test_accuracy': float(best_result['test_accuracy']),
            'cv_score': float(best_result['cv_mean']),
            'cv_std': float(best_result['cv_std']),
            'features': [
                'raw_latency',
                'log_latency',
                'squared_latency',
                'latency_bins',
                'normalized_latency'
            ],
            'per_class_performance': {}
        }
        
        # Add per-class metrics
        for label in self.encoder.classes_:
            if label in report:
                metadata['per_class_performance'][label] = {
                    'precision': float(report[label]['precision']),
                    'recall': float(report[label]['recall']),
                    'f1_score': float(report[label]['f1-score'])
                }
        
        metadata_path = self.ebpf_dir / "cause_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"  Metadata saved: {metadata_path}")
        
        self.print_success("Model saved")
        
        return {
            'model_path': str(model_path),
            'scaler_path': str(scaler_path),
            'encoder_path': str(encoder_path),
            'metadata_path': str(metadata_path)
        }
    
    # ===================================================================
    # MAIN TRAINING PIPELINE
    # ===================================================================
    
    def train(self):
        """Complete training pipeline"""
        self.print_header("TRAINING CAUSE CLASSIFIER")
        
        # Step 1: Load
        if not self.load_dataset():
            return False
        
        # Step 2-3: Prepare
        if not self.prepare_data():
            return False
        
        # Step 4: Train models
        best_result = self.train_models()
        
        # Step 5: Evaluate
        report = self.evaluate_model(best_result)
        
        # Step 6: Save
        paths = self.save_model(best_result, report)
        
        # Summary
        self.print_header("✓ TRAINING COMPLETE")
        
        print("Saved files:")
        for key, path in paths.items():
            print(f"  • {path}")
        
        print(f"\nModel Performance:")
        print(f"  Test Accuracy: {best_result['test_accuracy']:.1%}")
        print(f"  CV Score: {best_result['cv_mean']:.1%} ± {best_result['cv_std']:.1%}")
        
        print(f"\nNext step:")
        print(f"  python3 explain_spikes.py")
        
        return True

if __name__ == "__main__":
    try:
        trainer = SpikeClassifierTrainer()
        success = trainer.train()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
