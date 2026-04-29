"""
Quick Start Guide for ML Anomaly Detection Pipeline
Shows how to use each component step-by-step
"""

import pandas as pd
from dataset_generator import DatasetGenerator
from model_trainer import AnomalyDetector, CauseClassifier, ModelEvaluator
from realtime_detector import RealtimeDetector, DetectionLogger
from ml_pipeline import MLPipeline


# ============================================================================
# PART 1: GENERATE DATASET FROM RAW COLLECTOR EVENTS
# ============================================================================

def example_1_generate_dataset():
    """
    Step 1: Convert raw eBPF collector events to ML-ready features
    
    You would have CSV files like:
    - ebpf_logs/baseline_events.csv (label 0)
    - ebpf_logs/cpu_contention_events.csv (label 1)
    - ebpf_logs/disk_io_events.csv (label 3)
    etc.
    """
    
    print("\n" + "="*60)
    print("EXAMPLE 1: Dataset Generation")
    print("="*60)
    
    gen = DatasetGenerator(window_size_ms=100, stride_ms=50)
    
    # List of your collector output files with their labels
    # Format: (path_to_events_csv, label)
    dataset_files = [
        # ('path/to/baseline_events.csv', 0),
        # ('path/to/cpu_contention_events.csv', 1),
        # ('path/to/disk_io_events.csv', 3),
    ]
    
    # If you have the files, combine them:
    if dataset_files:
        dataset = gen.combine_datasets(dataset_files)
        gen.save_dataset(dataset, 'training_dataset.csv')
    else:
        print("\nTo use this example:")
        print("1. Collect data using the eBPF collector for each workload")
        print("2. Each collector run outputs events.csv")
        print("3. List the paths with their labels in dataset_files")
        print("4. Call gen.combine_datasets(dataset_files)")


# ============================================================================
# PART 2: TRAIN MODELS
# ============================================================================

def example_2_train_models():
    """
    Step 2: Train anomaly detection and cause classification models
    """
    
    print("\n" + "="*60)
    print("EXAMPLE 2: Model Training")
    print("="*60)
    
    # Load prepared dataset
    dataset = pd.read_csv('training_dataset.csv')
    
    # Initialize pipeline (automatically creates ml_model directory)
    pipeline = MLPipeline(output_dir='ml_model')
    
    # Train anomaly detector (Isolation Forest)
    print("\nTraining Anomaly Detector...")
    anomaly_stats = pipeline.train_anomaly_detector(dataset, contamination=0.1)
    print(f"  Detected {anomaly_stats.get('n_detected_anomalies')} anomalies in training data")
    
    # Train cause classifier (Random Forest)
    print("\nTraining Cause Classifier...")
    classifier_stats = pipeline.train_cause_classifier(
        dataset,
        model_type='random_forest',
        hyperparameter_tuning=False
    )
    print(f"  Train accuracy: {classifier_stats.get('train_accuracy'):.4f}")
    print(f"  Validation accuracy: {classifier_stats.get('validation_accuracy'):.4f}")
    
    # Alternative: XGBoost classifier (better performance but slower)
    # pipeline.train_cause_classifier(dataset, model_type='xgboost')
    
    # Save configuration
    pipeline.save_pipeline_config()
    
    return pipeline


# ============================================================================
# PART 3: REAL-TIME DETECTION
# ============================================================================

def example_3_realtime_detection():
    """
    Step 3: Use trained models for real-time detection
    """
    
    print("\n" + "="*60)
    print("EXAMPLE 3: Real-time Anomaly Detection")
    print("="*60)
    
    # Initialize detector with trained models
    detector = RealtimeDetector(
        anomaly_model_path='ml_model/anomaly_detector.pkl',
        cause_model_path='ml_model/cause_classifier.pkl',
        window_size_ms=100,
        alert_threshold=0.7
    )
    
    # Example 1: Add raw events (as they come from collector)
    events = [
        {'pid': 123, 'latency_ns': 1000000, 'ts_ns': 1000, 'cpu_id': 0, 'priority': 0, 'comm': 'test'},
        {'pid': 124, 'latency_ns': 1500000, 'ts_ns': 2000, 'cpu_id': 1, 'priority': 0, 'comm': 'test'},
    ]
    detector.add_events_batch(events)
    
    # Example 2: Full detection (both anomaly detection + cause classification)
    result = detector.full_detection()
    
    print("\nDetection Result:")
    if result['anomaly_detection']:
        print(f"  Anomaly detected: {result['anomaly_detection']['is_anomaly']}")
        print(f"  Anomaly score: {result['anomaly_detection']['anomaly_score']:.4f}")
    
    if result['cause_classification']:
        print(f"  Predicted cause: {result['cause_classification']['predicted_cause']}")
        print(f"  Confidence: {result['cause_classification']['confidence']:.2%}")
    
    if 'alert' in result:
        print(f"  ⚠️  Alert: {result['alert_message']}")
    
    return detector


# ============================================================================
# PART 4: INTEGRATE WITH COLLECTOR
# ============================================================================

def example_4_collector_integration():
    """
    Step 4: Integrate with the live eBPF collector
    
    This shows how to:
    1. Read events from collector
    2. Stream to detector
    3. Log results
    """
    
    print("\n" + "="*60)
    print("EXAMPLE 4: Collector Integration")
    print("="*60)
    
    import csv
    import time
    
    # Initialize detector and logger
    detector = RealtimeDetector(
        anomaly_model_path='ml_model/anomaly_detector.pkl',
        cause_model_path='ml_model/cause_classifier.pkl'
    )
    logger = DetectionLogger('ml_model/detection_results.jsonl')
    
    def detection_callback(result):
        """Called when detection finishes"""
        logger.log_detection(result)
        
        # Print summary every 10 detections
        if len(logger.detections) % 10 == 0:
            stats = logger.get_anomaly_statistics()
            print(f"\nProgress: {stats.get('total_detections')} detections, "
                  f"{stats.get('anomaly_percentage'):.1f}% anomalies")
    
    # Start monitoring in background
    monitor_thread = detector.start_monitoring(callback=detection_callback, interval_sec=1.0)
    
    # Read events from collector and add to detector
    try:
        # Example: read from CSV file written by collector
        with open('ebpf_logs/ebpf_events.csv', 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                event = {
                    'pid': int(row['pid']),
                    'tgid': int(row['tgid']),
                    'latency_ns': int(row['latency_ns']),
                    'ts_ns': int(row['ts_ns']),
                    'cpu_id': int(row['cpu_id']),
                    'priority': int(row['priority']),
                    'comm': row['comm'],
                }
                detector.add_event(event)
                time.sleep(0.001)  # Simulate stream
    
    except FileNotFoundError:
        print("ebpf_logs/ebpf_events.csv not found - showing example format")
    
    finally:
        detector.stop_monitoring()
    
    # Print final statistics
    stats = logger.get_anomaly_statistics()
    print(f"\nFinal Statistics:")
    print(f"  Total detections: {stats.get('total_detections')}")
    print(f"  Total anomalies: {stats.get('total_anomalies')}")
    print(f"  Anomaly rate: {stats.get('anomaly_percentage'):.2f}%")
    print(f"  Cause distribution: {stats.get('cause_distribution')}")


# ============================================================================
# PART 5: ANALYZING RESULTS
# ============================================================================

def example_5_analyze_results():
    """
    Step 5: Analyze detection results and generate reports
    """
    
    print("\n" + "="*60)
    print("EXAMPLE 5: Results Analysis")
    print("="*60)
    
    logger = DetectionLogger('ml_model/detection_results.jsonl')
    
    # Get statistics
    stats = logger.get_anomaly_statistics()
    
    print("\nAnomaly Statistics:")
    print(f"  Total detections: {stats.get('total_detections')}")
    print(f"  Total anomalies: {stats.get('total_anomalies')}")
    print(f"  Anomaly rate: {stats.get('anomaly_percentage'):.2f}%")
    print(f"  Average anomaly score: {stats.get('average_anomaly_score'):.4f}")
    
    print("\nCause Distribution:")
    for cause, count in stats.get('cause_distribution', {}).items():
        print(f"  {cause}: {count}")
    
    # Load recent detections
    recent = logger.load_logs(limit=10)
    print(f"\nRecent detections (last {len(recent)}):")
    for i, detection in enumerate(recent[-5:], 1):
        print(f"  {i}. {detection.get('timestamp')}")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    print("\n" + "="*60)
    print("ML ANOMALY DETECTION - QUICK START GUIDE")
    print("="*60)
    
    print("""
This guide shows you how to use the ML anomaly detection pipeline.

Follow these steps in order:

1. DATASET GENERATION (example_1_generate_dataset)
   - Collect data from your workloads using the eBPF collector
   - Convert raw events to ML features
   
2. MODEL TRAINING (example_2_train_models)
   - Train anomaly detector (Isolation Forest)
   - Train cause classifier (Random Forest)
   - Evaluate performance
   
3. REAL-TIME DETECTION (example_3_realtime_detection)
   - Load trained models
   - Run detection on new data
   
4. COLLECTOR INTEGRATION (example_4_collector_integration)
   - Integrate with live eBPF collector
   - Stream events to detector
   - Log results
   
5. RESULTS ANALYSIS (example_5_analyze_results)
   - Analyze detection statistics
   - Generate reports

To run examples, uncomment and run:
""")
    
    # Uncomment to run examples
    # example_1_generate_dataset()
    # pipeline = example_2_train_models()
    # detector = example_3_realtime_detection()
    # example_4_collector_integration()
    # example_5_analyze_results()
    
    print("\nSee the code for more details and usage patterns.")
