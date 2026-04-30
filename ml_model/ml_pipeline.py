"""
End-to-End ML Pipeline for Scheduling Latency Anomaly Detection
Full workflow: Data preparation -> Training -> Evaluation -> Deployment
"""

import pandas as pd
import numpy as np
from pathlib import Path
import argparse
import json
from datetime import datetime
from typing import Dict

from dataset_generator import DatasetGenerator
from model_trainer import AnomalyDetector, CauseClassifier, ModelEvaluator
from realtime_detector import RealtimeDetector, DetectionLogger


class MLPipeline:
    """Complete ML pipeline orchestration"""
    
    def __init__(self, output_dir: str = 'ml_model'):
        """
        Initialize pipeline
        
        Args:
            output_dir: Directory for models and outputs
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.dataset_gen = DatasetGenerator(window_size_ms=100, stride_ms=50)
        self.anomaly_detector = None
        self.cause_classifier = None
        self.evaluation_results = {}
        
    def prepare_dataset(self, input_files: list, output_csv: str = None) -> pd.DataFrame:
        """
        Prepare dataset from raw collector events
        
        Args:
            input_files: List of (csv_path, label) tuples
            output_csv: Save prepared dataset to CSV
            
        Returns:
            Prepared dataset
        """
        print("\n" + "="*60)
        print("STEP 1: DATASET PREPARATION")
        print("="*60)
        
        dataset = self.dataset_gen.combine_datasets(input_files)
        
        if output_csv is None:
            output_csv = self.output_dir / 'training_dataset.csv'
        
        self.dataset_gen.save_dataset(dataset, str(output_csv))
        
        return dataset
    
    def train_anomaly_detector(self, dataset: pd.DataFrame, 
                              contamination: float = 0.1) -> Dict:
        """
        Train anomaly detection model
        
        Args:
            dataset: Prepared dataset
            contamination: Contamination parameter
            
        Returns:
            Training statistics
        """
        print("\n" + "="*60)
        print("STEP 2: ANOMALY DETECTION TRAINING")
        print("="*60)
        
        # Use only model features; drop ordering / metadata columns that can leak label information.
        X = dataset.drop(
            ['label', 'timestamp', 'ts_ns', 'window_start_ts', 'window_end_ts', 'priority_max', 'highest_prio'],
            axis=1,
            errors='ignore'
        )
        
        self.anomaly_detector = AnomalyDetector(contamination=contamination)
        stats = self.anomaly_detector.train(X)
        
        # Save model
        model_path = self.output_dir / 'anomaly_detector.pkl'
        self.anomaly_detector.save(str(model_path))
        
        self.evaluation_results['anomaly_detector'] = stats
        return stats
    
    def train_cause_classifier(self, dataset: pd.DataFrame,
                              model_type: str = 'random_forest',
                              test_size: float = 0.2,
                              hyperparameter_tuning: bool = False) -> Dict:
        """
        Train cause classification model
        
        Args:
            dataset: Prepared dataset
            model_type: Type of model to train
            test_size: Fraction of data for testing
            hyperparameter_tuning: Enable grid search
            
        Returns:
            Training statistics
        """
        print("\n" + "="*60)
        print("STEP 3: CAUSE CLASSIFICATION TRAINING")
        print("="*60)
        
        # Prepare data
        feature_cols = [col for col in dataset.columns
                       if col not in ['label', 'timestamp', 'ts_ns', 'window_start_ts', 'window_end_ts', 'priority_max', 'highest_prio']]
        X = dataset[feature_cols]
        y = dataset['label']
        
        # Split data
        train_df, test_df = self.dataset_gen.split_train_test(
            dataset.copy(), test_ratio=test_size
        )

        y_train = train_df['label']
        y_test = test_df['label']
        X_train = train_df.drop(['label', 'timestamp', 'ts_ns', 'window_start_ts', 'window_end_ts', 'priority_max', 'highest_prio'], axis=1, errors='ignore')
        X_test = test_df.drop(['label', 'timestamp', 'ts_ns', 'window_start_ts', 'window_end_ts', 'priority_max', 'highest_prio'], axis=1, errors='ignore')
        
        # Train model
        self.cause_classifier = CauseClassifier(model_type=model_type)
        stats = self.cause_classifier.train(
            X_train,
            y_train,
            hyperparameter_tuning=hyperparameter_tuning
        )
        
        # Evaluate on test set
        eval_results = ModelEvaluator.evaluate_classifier(
            self.cause_classifier, X_test, y_test,
            output_dir=str(self.output_dir)
        )
        
        # Save model
        model_path = self.output_dir / 'cause_classifier.pkl'
        self.cause_classifier.save(str(model_path))
        
        # Save feature importance
        importance_df = self.cause_classifier.get_feature_importance(top_n=20)
        if importance_df is not None:
            importance_df.to_csv(
                self.output_dir / 'feature_importance.csv',
                index=False
            )
        
        self.evaluation_results['cause_classifier'] = {**stats, **eval_results}
        
        return stats
    
    def save_pipeline_config(self):
        """Save pipeline configuration and results"""
        config = {
            'timestamp': datetime.now().isoformat(),
            'anomaly_detector': self.evaluation_results.get('anomaly_detector', {}),
            'cause_classifier': self.evaluation_results.get('cause_classifier', {}),
            'model_paths': {
                'anomaly_detector': 'anomaly_detector.pkl',
                'cause_classifier': 'cause_classifier.pkl',
            }
        }
        
        config_path = self.output_dir / 'pipeline_config.json'
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2, default=str)
        
        print(f"\nPipeline config saved to {config_path}")
        
        return config
    
    def print_summary(self):
        """Print training summary"""
        print("\n" + "="*60)
        print("TRAINING SUMMARY")
        print("="*60)
        
        if 'anomaly_detector' in self.evaluation_results:
            ad_stats = self.evaluation_results['anomaly_detector']
            print(f"\nAnomaly Detector:")
            print(f"  Training samples: {ad_stats.get('n_training_samples', 'N/A')}")
            print(f"  Detected anomalies: {ad_stats.get('n_detected_anomalies', 'N/A')}")
            print(f"  Anomaly percentage: {ad_stats.get('anomaly_percentage', 'N/A'):.2f}%")
        
        if 'cause_classifier' in self.evaluation_results:
            cc_stats = self.evaluation_results['cause_classifier']
            print(f"\nCause Classifier ({cc_stats.get('model_type', 'unknown')}):")
            print(f"  Training samples: {cc_stats.get('n_training_samples', 'N/A')}")
            print(f"  Validation samples: {cc_stats.get('n_validation_samples', 'N/A')}")
            print(f"  Train accuracy: {cc_stats.get('train_accuracy', 'N/A'):.4f}")
            print(f"  Validation accuracy: {cc_stats.get('validation_accuracy', 'N/A'):.4f}")
            print(f"  Cross-validation: {cc_stats.get('cv_mean', 'N/A'):.4f} ± {cc_stats.get('cv_std', 'N/A'):.4f}")
            
            if 'accuracy' in cc_stats:
                print(f"\n  Test Set Metrics:")
                print(f"    Accuracy: {cc_stats.get('accuracy', 'N/A'):.4f}")
                print(f"    Precision: {cc_stats.get('precision', 'N/A'):.4f}")
                print(f"    Recall: {cc_stats.get('recall', 'N/A'):.4f}")
                print(f"    F1-Score: {cc_stats.get('f1_score', 'N/A'):.4f}")
        
        print(f"\n✓ Models saved to: {self.output_dir}")


def main():
    parser = argparse.ArgumentParser(
        description='Train ML models for scheduling latency anomaly detection'
    )
    parser.add_argument(
        '--prepare-only', action='store_true',
        help='Only prepare dataset without training'
    )
    parser.add_argument(
        '--dataset', type=str,
        help='Path to dataset CSV (skip preparation if provided)'
    )
    parser.add_argument(
        '--anomaly-only', action='store_true',
        help='Train only anomaly detector'
    )
    parser.add_argument(
        '--classifier-only', action='store_true',
        help='Train only cause classifier'
    )
    parser.add_argument(
        '--output-dir', type=str, default='ml_model',
        help='Output directory for models'
    )
    parser.add_argument(
        '--tuning', action='store_true',
        help='Enable hyperparameter tuning'
    )
    
    args = parser.parse_args()
    
    # Initialize pipeline
    pipeline = MLPipeline(output_dir=args.output_dir)
    
    # Prepare dataset
    if args.dataset:
        print(f"Loading dataset from {args.dataset}")
        dataset = pd.read_csv(args.dataset)
    else:
        print("\nTo prepare a dataset, provide input CSV files:")
        print("Example usage:")
        print("  python ml_pipeline.py --prepare-only")
        print("\nYou need to collect data from your workloads first using the collector")
        print("Then combine them using DatasetGenerator.combine_datasets()")
        
        if args.prepare_only:
            return
        
        # For now, create a sample dataset
        print("Creating sample dataset for demonstration...")
        
        # Create synthetic data for demonstration
        n_samples = 1000
        data = {
            'latency_mean': np.random.exponential(1000, n_samples),
            'latency_std': np.random.exponential(500, n_samples),
            'latency_min': np.abs(np.random.normal(100, 50, n_samples)),
            'latency_max': np.random.exponential(5000, n_samples),
            'latency_p50': np.random.exponential(1000, n_samples),
            'latency_p75': np.random.exponential(1500, n_samples),
            'latency_p90': np.random.exponential(2500, n_samples),
            'latency_p95': np.random.exponential(3500, n_samples),
            'latency_p99': np.random.exponential(5000, n_samples),
            'latency_skewness': np.random.normal(1, 0.5, n_samples),
            'latency_kurtosis': np.random.exponential(2, n_samples),
            'latency_median_abs_dev': np.random.exponential(200, n_samples),
            'event_count': np.random.randint(10, 500, n_samples),
            'event_rate': np.random.exponential(100, n_samples),
            'time_span_ns': np.random.exponential(1e8, n_samples),
            'num_unique_cpus': np.random.randint(1, 8, n_samples),
            'cpu_concentration': np.random.beta(2, 5, n_samples),
            'priority_mean': np.random.normal(0, 10, n_samples),
            'priority_std': np.random.exponential(5, n_samples),
            'priority_min': np.random.normal(-20, 5, n_samples),
            'priority_max': np.random.normal(20, 5, n_samples),
            'outlier_ratio_3sigma': np.random.beta(2, 10, n_samples),
            'tail_latency_ratio': np.random.beta(2, 10, n_samples),
            'label': np.random.randint(0, 9, n_samples),
        }
        dataset = pd.DataFrame(data)
        
        # Save for reference
        dataset.to_csv(pipeline.output_dir / 'demo_dataset.csv', index=False)
    
    # Train models
    if not args.classifier_only:
        pipeline.train_anomaly_detector(dataset)
    
    if not args.anomaly_only:
        pipeline.train_cause_classifier(dataset, hyperparameter_tuning=args.tuning)
    
    # Save configuration
    pipeline.save_pipeline_config()
    
    # Print summary
    pipeline.print_summary()
    
    print("\n" + "="*60)
    print("✓ Training complete!")
    print("="*60)
    print("\nNext steps:")
    print("1. Use RealtimeDetector to monitor new data")
    print("2. Example:")
    print("   detector = RealtimeDetector(")
    print("       anomaly_model_path='ml_model/anomaly_detector.pkl',")
    print("       cause_model_path='ml_model/cause_classifier.pkl'")
    print("   )")
    print("   result = detector.full_detection()")


if __name__ == "__main__":
    main()
