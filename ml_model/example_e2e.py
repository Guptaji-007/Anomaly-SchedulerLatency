#!/usr/bin/env python3
"""
Complete End-to-End ML Anomaly Detection Example
Shows full workflow: Data Collection → Training → Real-time Detection
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np
import time

# Add ml_model to path
sys.path.insert(0, str(Path(__file__).parent))

from dataset_generator import DatasetGenerator
from model_trainer import AnomalyDetector, CauseClassifier, ModelEvaluator
from realtime_detector import RealtimeDetector, DetectionLogger
from ml_pipeline import MLPipeline
from utils import ValidationTest, PerformanceProfiler, ReportGenerator
from config import Config, get_config


def generate_synthetic_data(output_dir: str = 'ml_model') -> str:
    """
    Generate synthetic training data for demonstration
    In production, use real collector data
    """
    print("\n" + "="*60)
    print("STEP 1: GENERATING SYNTHETIC DATA")
    print("="*60)
    
    Path(output_dir).mkdir(exist_ok=True)
    
    # Generate data for each workload class
    n_samples_per_class = 200
    n_features = 23
    
    all_data = []
    
    for label in range(9):
        print(f"\nGenerating {n_samples_per_class} samples for class {label}...")
        
        # Generate class-specific patterns
        if label == 0:  # Baseline - low latency, low variance
            mean_latency = 500
            std_latency = 100
            cpu_concentration = 0.3
        elif label == 1:  # CPU contention - high latency, high variance
            mean_latency = 5000
            std_latency = 2000
            cpu_concentration = 0.8
        elif label == 2:  # Heavy contention
            mean_latency = 8000
            std_latency = 3000
            cpu_concentration = 0.9
        elif label == 3:  # Disk IO - spiky latency
            mean_latency = 10000
            std_latency = 4000
            cpu_concentration = 0.5
        elif label == 4:  # Memory pressure
            mean_latency = 6000
            std_latency = 2500
            cpu_concentration = 0.6
        elif label == 5:  # Lock contention
            mean_latency = 7000
            std_latency = 3000
            cpu_concentration = 0.85
        elif label == 6:  # IPC communication
            mean_latency = 4000
            std_latency = 1500
            cpu_concentration = 0.4
        elif label == 7:  # Context switching
            mean_latency = 5500
            std_latency = 2200
            cpu_concentration = 0.7
        else:  # Mixed
            mean_latency = 6500
            std_latency = 2800
            cpu_concentration = 0.65
        
        # Generate samples
        for _ in range(n_samples_per_class):
            sample = {
                'latency_mean': np.abs(np.random.normal(mean_latency, std_latency/2)),
                'latency_std': np.abs(np.random.exponential(std_latency/2)),
                'latency_min': np.abs(np.random.normal(mean_latency/5, std_latency/5)),
                'latency_max': np.random.exponential(mean_latency * 3),
                'latency_p50': np.abs(np.random.normal(mean_latency * 0.8, std_latency/3)),
                'latency_p75': np.abs(np.random.normal(mean_latency * 1.2, std_latency/2)),
                'latency_p90': np.abs(np.random.normal(mean_latency * 1.5, std_latency * 0.7)),
                'latency_p95': np.abs(np.random.normal(mean_latency * 2, std_latency)),
                'latency_p99': np.random.exponential(mean_latency * 2.5),
                'latency_skewness': np.random.normal(1.5, 0.5),
                'latency_kurtosis': np.random.exponential(2),
                'latency_median_abs_dev': np.abs(np.random.exponential(std_latency/3)),
                'event_count': np.random.randint(50, 500),
                'event_rate': np.random.exponential(100),
                'time_span_ns': np.random.exponential(1e8),
                'num_unique_cpus': np.random.randint(1, 8),
                'cpu_concentration': np.clip(cpu_concentration + np.random.normal(0, 0.1), 0, 1),
                'priority_mean': np.random.normal(0, 5),
                'priority_std': np.abs(np.random.normal(5, 2)),
                'priority_min': np.random.normal(-10, 5),
                'priority_max': np.random.normal(10, 5),
                'outlier_ratio_3sigma': np.clip(np.random.beta(2, 10), 0, 1),
                'tail_latency_ratio': np.clip(np.random.beta(2, 10), 0, 1),
                'label': label,
            }
            all_data.append(sample)
    
    # Save dataset
    dataset = pd.DataFrame(all_data)
    dataset_path = f'{output_dir}/training_dataset.csv'
    dataset.to_csv(dataset_path, index=False)
    
    print(f"\n✓ Generated {len(dataset)} samples")
    print(f"✓ Saved to {dataset_path}")
    print(f"  Class distribution:\n{dataset['label'].value_counts().sort_index()}")
    
    return dataset_path


def train_models(dataset_path: str, output_dir: str = 'ml_model'):
    """Train anomaly detection and cause classification models"""
    
    print("\n" + "="*60)
    print("STEP 2: TRAINING MODELS")
    print("="*60)
    
    # Load dataset
    dataset = pd.read_csv(dataset_path)
    
    # Initialize pipeline
    pipeline = MLPipeline(output_dir=output_dir)
    
    # Train anomaly detector
    print("\nTraining Anomaly Detector (Isolation Forest)...")
    X = dataset.drop('label', axis=1)
    anomaly_stats = pipeline.train_anomaly_detector(X, contamination=0.1)
    
    # Train cause classifier
    print("\nTraining Cause Classifier (Random Forest)...")
    classifier_stats = pipeline.train_cause_classifier(
        dataset,
        model_type='random_forest',
        hyperparameter_tuning=False
    )
    
    # Save configuration
    pipeline.save_pipeline_config()
    pipeline.print_summary()
    
    return pipeline


def run_realtime_detection(pipeline_config: dict = None, output_dir: str = 'ml_model'):
    """Run real-time anomaly detection"""
    
    print("\n" + "="*60)
    print("STEP 3: REAL-TIME ANOMALY DETECTION")
    print("="*60)
    
    # Initialize detector
    detector = RealtimeDetector(
        anomaly_model_path=f'{output_dir}/anomaly_detector.pkl',
        cause_model_path=f'{output_dir}/cause_classifier.pkl',
        window_size_ms=100,
        alert_threshold=0.7
    )
    
    logger = DetectionLogger(f'{output_dir}/detection_results.jsonl')
    
    print("\nSimulating real-time event stream...")
    print("Generating synthetic events and running detection...")
    
    n_events = 500
    
    for i in range(0, n_events, 100):
        print(f"\n  Processing events {i}-{i+100}...")
        
        # Generate synthetic events
        for j in range(100):
            event = {
                'pid': np.random.randint(100, 10000),
                'latency_ns': np.random.exponential(1000000),
                'ts_ns': int(time.time() * 1e9) + j * 1000,
                'cpu_id': np.random.randint(0, 8),
                'priority': np.random.randint(-20, 20),
                'comm': f'worker_{i+j}',
            }
            detector.add_event(event)
        
        # Run detection every 100 events
        result = detector.full_detection()
        
        if result['anomaly_detection'] and result['anomaly_detection']['is_anomaly']:
            print(f"    ⚠️  Anomaly detected!")
            if result['cause_classification']:
                print(f"       Cause: {result['cause_classification']['predicted_cause']}")
                print(f"       Confidence: {result['cause_classification']['confidence']:.2%}")
        
        logger.log_detection(result)
    
    # Print statistics
    stats = logger.get_anomaly_statistics()
    
    print("\n" + "="*60)
    print("DETECTION STATISTICS")
    print("="*60)
    print(f"Total detections: {stats.get('total_detections')}")
    print(f"Detected anomalies: {stats.get('total_anomalies')}")
    print(f"Anomaly rate: {stats.get('anomaly_percentage', 0):.2f}%")
    
    if stats.get('cause_distribution'):
        print("\nDetected causes:")
        for cause, count in sorted(
            stats['cause_distribution'].items(),
            key=lambda x: x[1],
            reverse=True
        ):
            print(f"  {cause}: {count}")
    
    return detector, logger


def performance_testing(detector: RealtimeDetector):
    """Test detector performance"""
    
    print("\n" + "="*60)
    print("STEP 4: PERFORMANCE TESTING")
    print("="*60)
    
    profiler = PerformanceProfiler()
    results = profiler.profile_detection_speed(detector, n_samples=1000)
    
    print("\nLatency Analysis:")
    for task, metrics in results.items():
        print(f"  {task}:")
        print(f"    Mean: {metrics['mean_ms']:.3f} ms")
        print(f"    Std:  {metrics['std_ms']:.3f} ms")
        print(f"    Min:  {metrics['min_ms']:.3f} ms")
        print(f"    Max:  {metrics['max_ms']:.3f} ms")


def main():
    """Run complete end-to-end example"""
    
    print("\n" + "="*70)
    print(" "*15 + "ML ANOMALY DETECTION - END-TO-END EXAMPLE")
    print("="*70)
    
    Config.print_config()
    
    output_dir = 'ml_model'
    
    # Step 1: Generate synthetic data
    dataset_path = generate_synthetic_data(output_dir)
    
    # Step 2: Train models
    pipeline = train_models(dataset_path, output_dir)
    
    # Step 3: Run real-time detection
    detector, logger = run_realtime_detection(output_dir=output_dir)
    
    # Step 4: Performance testing
    performance_testing(detector)
    
    # Step 5: Generate report
    print("\n" + "="*60)
    print("STEP 5: GENERATING REPORT")
    print("="*60)
    
    ReportGenerator.print_detection_summary(logger)
    
    print("\n" + "="*70)
    print(" "*20 + "✓ EXAMPLE COMPLETE!")
    print("="*70)
    
    print("\nNext steps:")
    print("1. Collect real data from your eBPF collector")
    print("2. Use DatasetGenerator to prepare your dataset")
    print("3. Retrain models with real data")
    print("4. Deploy RealtimeDetector for production use")
    print("\nFor more information, see README.md")


if __name__ == "__main__":
    main()
