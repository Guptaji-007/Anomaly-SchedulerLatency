# ML Anomaly Detection for Scheduling Latency

Complete machine learning pipeline for detecting and classifying anomalies in Linux kernel scheduler latency.

## Overview

This module provides:

1. **Dataset Generation** - Convert raw eBPF collector events to ML features
2. **Model Training** - Train anomaly detection and cause classification models
3. **Real-time Detection** - Detect anomalies and classify causes in real-time
4. **Integration** - Seamlessly integrate with the eBPF collector

## Architecture

```
Raw eBPF Events (collector.c)
        ↓
  Dataset Generator
        ↓
Feature Extraction (23 features per window)
        ↓
    Training Set
        ↓
   Model Training
  ┌──────┴──────┐
  ↓             ↓
Anomaly      Cause
Detector    Classifier
  ↓             ↓
(IF)        (RF/XGB)
        ↓
Real-time Detection Engine
        ↓
  Alerts & Logs
```

## Features

### Dataset Features (23 per window)

**Latency Statistics:**
- Mean, Std, Min, Max, Median (p50)
- Percentiles: p75, p90, p95, p99
- Skewness, Kurtosis, Median Absolute Deviation

**Temporal Features:**
- Event count and rate
- Time span of window

**Resource Features:**
- Number of unique CPUs
- CPU concentration (load skew)
- Priority statistics (mean, std, min, max)

**Anomaly Indicators:**
- 3-sigma outlier ratio
- Tail latency ratio (p95+)

### Models

**Anomaly Detection: Isolation Forest**
- One-class anomaly detector
- Unsupervised learning
- Detects deviation from baseline
- Configurable contamination rate

**Cause Classification: Random Forest / XGBoost**
- Multi-class classifier (9 workload types)
- Supervised learning
- Identifies root cause of anomaly
- High interpretability with feature importance

### Workload Classes (9)

```
0: baseline             - Minimal activity
1: cpu_contention       - CPU resource contention
2: heavy_contention     - Severe contention
3: disk_io              - Heavy disk I/O
4: memory_pressure      - Memory pressure
5: lock_contention      - Lock contention
6: ipc_communication    - IPC patterns
7: context_switching    - High context switches
8: mixed                - Combined workloads
```

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### 1. Generate Dataset from Collector Events

```python
from dataset_generator import DatasetGenerator

gen = DatasetGenerator(window_size_ms=100, stride_ms=50)

# Combine multiple workload recordings
dataset_files = [
    ('ebpf_logs/baseline_events.csv', 0),
    ('ebpf_logs/cpu_contention_events.csv', 1),
    ('ebpf_logs/disk_io_events.csv', 3),
]

dataset = gen.combine_datasets(dataset_files)
gen.save_dataset(dataset, 'training_dataset.csv')
```

### 2. Train Models

```python
from ml_pipeline import MLPipeline
import pandas as pd

pipeline = MLPipeline(output_dir='ml_model')

# Load dataset
dataset = pd.read_csv('training_dataset.csv')

# Train anomaly detector
pipeline.train_anomaly_detector(dataset, contamination=0.1)

# Train cause classifier
pipeline.train_cause_classifier(dataset, model_type='random_forest')

# Save configuration
pipeline.save_pipeline_config()
```

### 3. Real-time Detection

```python
from realtime_detector import RealtimeDetector, DetectionLogger

# Initialize detector with trained models
detector = RealtimeDetector(
    anomaly_model_path='ml_model/anomaly_detector.pkl',
    cause_model_path='ml_model/cause_classifier.pkl',
    window_size_ms=100,
    alert_threshold=0.7
)

# Add events from collector
events = [
    {'pid': 123, 'latency_ns': 1000000, 'ts_ns': 1000, ...},
    {'pid': 124, 'latency_ns': 1500000, 'ts_ns': 2000, ...},
]
detector.add_events_batch(events)

# Run detection
result = detector.full_detection()

# Check results
if result['anomaly_detection']['is_anomaly']:
    print(f"Anomaly: {result['cause_classification']['predicted_cause']}")
    print(f"Confidence: {result['cause_classification']['confidence']:.2%}")
```

## Module Details

### dataset_generator.py

**DatasetGenerator Class:**
- `load_events()` - Load raw events from CSV
- `extract_window_features()` - Extract 23 features from time window
- `generate_dataset()` - Create ML-ready dataset
- `combine_datasets()` - Merge multiple workload recordings
- `save_dataset()` - Save to CSV
- `split_train_test()` - Stratified train/test split

**Usage:**
```python
gen = DatasetGenerator(window_size_ms=100, stride_ms=50)

# Extract features
dataset = gen.generate_dataset('events.csv', label=0)

# Combine multiple workloads
combined = gen.combine_datasets([
    ('baseline.csv', 0),
    ('cpu_contention.csv', 1),
])
```

### model_trainer.py

**AnomalyDetector Class:**
- Isolation Forest-based anomaly detection
- Unsupervised learning
- Methods:
  - `train()` - Train on normal data
  - `predict()` - Detect anomalies
  - `get_anomaly_indices()` - Get anomaly samples
  - `save() / load()` - Model persistence

**CauseClassifier Class:**
- Multi-class classification (9 workload types)
- Supports: Random Forest, Gradient Boosting, XGBoost
- Methods:
  - `train()` - Train with hyperparameter tuning option
  - `predict()` - Classify cause
  - `predict_with_confidence()` - Include confidence scores
  - `get_feature_importance()` - Interpret model decisions
  - `save() / load()` - Model persistence

**ModelEvaluator Class:**
- Comprehensive evaluation metrics
- Generates confusion matrix, feature importance plots
- Methods:
  - `evaluate_classifier()` - Full evaluation report

**Usage:**
```python
from model_trainer import AnomalyDetector, CauseClassifier

# Train anomaly detector
detector = AnomalyDetector(contamination=0.1)
detector.train(X_normal)
predictions, scores = detector.predict(X_test)

# Train cause classifier
classifier = CauseClassifier(model_type='random_forest')
classifier.train(X_train, y_train)
predictions, probs = classifier.predict(X_test)
importance = classifier.get_feature_importance(top_n=15)
```

### realtime_detector.py

**RealtimeDetector Class:**
- Real-time anomaly detection and cause classification
- Circular event buffer with configurable size
- Thread-safe operations
- Background monitoring capability

**Key Methods:**
- `add_event()` - Add single event
- `add_events_batch()` - Add multiple events
- `detect_anomaly()` - Run anomaly detection
- `classify_cause()` - Run cause classification
- `full_detection()` - Combined detection + classification
- `start_monitoring()` - Background monitoring thread
- `get_buffer_stats()` - Buffer statistics

**DetectionLogger Class:**
- Log detection results to JSONL
- Analyze detection statistics
- Methods:
  - `log_detection()` - Save detection result
  - `load_logs()` - Load historical results
  - `get_anomaly_statistics()` - Aggregate statistics

**Usage:**
```python
from realtime_detector import RealtimeDetector, DetectionLogger

detector = RealtimeDetector(
    anomaly_model_path='anomaly_detector.pkl',
    cause_model_path='cause_classifier.pkl'
)

# Add events
detector.add_events_batch(events)

# Detect
result = detector.full_detection()

# Monitor in background
logger = DetectionLogger('results.jsonl')
detector.start_monitoring(
    callback=logger.log_detection,
    interval_sec=1.0
)
```

### ml_pipeline.py

**MLPipeline Class:**
- End-to-end training orchestration
- Automated preparation → training → evaluation → deployment

**Methods:**
- `prepare_dataset()` - Generate dataset from raw events
- `train_anomaly_detector()` - Train anomaly model
- `train_cause_classifier()` - Train cause model
- `save_pipeline_config()` - Save trained configuration
- `print_summary()` - Print training results

**Usage:**
```bash
# Full pipeline with hyperparameter tuning
python ml_pipeline.py --tuning

# Prepare dataset only
python ml_pipeline.py --prepare-only

# Use existing dataset
python ml_pipeline.py --dataset training_dataset.csv

# Train only specific model
python ml_pipeline.py --classifier-only
```

## Data Format

### Input: Collector Events CSV

Expected columns:
```
pid, tgid, latency_ns, ts_ns, cpu_id, priority, comm
123,  456,  1000000,   1000,    0,     0,      "myapp"
124,  456,  1500000,   2000,    1,     0,      "myapp"
```

### Output: ML Dataset CSV

After feature extraction:
```
latency_mean, latency_std, latency_p99, ..., label
1023.5,       512.3,       5000.0,      ..., 1
1245.2,       623.1,       6200.0,      ..., 1
```

## Workflow: From Collector to Detection

```
1. COLLECT DATA
   └─ Run collector for each workload
   └─ Save events.csv for each

2. PREPARE DATASET
   └─ Load events.csv files
   └─ Extract 23 features per window
   └─ Create training_dataset.csv

3. TRAIN MODELS
   └─ Train Anomaly Detector (Isolation Forest)
   └─ Train Cause Classifier (Random Forest)
   └─ Evaluate performance

4. DEPLOY & DETECT
   └─ Load models in RealtimeDetector
   └─ Stream events from collector
   └─ Generate alerts for anomalies
   └─ Classify root cause

5. ANALYZE
   └─ Review detection logs
   └─ Generate statistics
   └─ Tune parameters if needed
```

## Configuration

### Dataset Generator

```python
gen = DatasetGenerator(
    window_size_ms=100,    # Feature extraction window (ms)
    stride_ms=50           # Sliding window stride (ms)
)
```

### Anomaly Detector

```python
detector = AnomalyDetector(
    contamination=0.1      # Expected anomaly fraction
)
```

### Cause Classifier

```python
classifier = CauseClassifier(
    model_type='random_forest'  # or 'gradient_boosting', 'xgboost'
)
```

### Real-time Detector

```python
detector = RealtimeDetector(
    anomaly_model_path='...',
    cause_model_path='...',
    window_size_ms=100,
    alert_threshold=0.7    # Min confidence for alerts
)
```

## Output Files

After training, ml_model/ contains:

```
ml_model/
├── training_dataset.csv          # Prepared dataset
├── anomaly_detector.pkl          # Trained anomaly model
├── cause_classifier.pkl          # Trained cause model
├── feature_importance.csv        # Top features for classifier
├── confusion_matrix.png          # Model evaluation plot
├── feature_importance.png        # Feature importance plot
├── pipeline_config.json          # Training configuration
└── detection_results.jsonl       # Real-time detection logs
```

## Performance Metrics

### Training Metrics

- Accuracy, Precision, Recall, F1-Score
- 5-fold cross-validation score
- Confusion matrix for all classes

### Detection Metrics

- Anomaly detection rate
- Classification confidence distribution
- Cause distribution statistics
- True positive / false positive rates

## Troubleshooting

### Low Classification Accuracy

1. **Insufficient training data** - Collect more samples per workload
2. **Imbalanced classes** - Use `class_weight='balanced'` in classifier
3. **Feature overlap** - Some workloads may have similar latency patterns
4. **Window size too small** - Increase window_size_ms for more stable features

### High False Positive Rate

1. **Lower contamination** - Reduce anomaly detector contamination parameter
2. **Adjust threshold** - Increase alert_threshold in RealtimeDetector
3. **Retrain on cleaner data** - Remove outliers before training

### Memory Issues

1. **Large event buffer** - Reduce events_buffer maxlen in RealtimeDetector
2. **Sliding window stride** - Increase stride_ms to reduce feature vectors

## Advanced Usage

### Hyperparameter Tuning

```python
pipeline = MLPipeline()
pipeline.train_cause_classifier(
    dataset,
    model_type='xgboost',
    hyperparameter_tuning=True  # Enable GridSearchCV
)
```

### Custom Feature Extraction

```python
def extract_custom_features(events: pd.DataFrame) -> Dict:
    return {
        'custom_feature': custom_calculation(events),
        ...
    }
```

### Feature Importance Analysis

```python
importance = classifier.get_feature_importance(top_n=20)
print(importance.to_string())
```

### Model Comparison

```python
for model_type in ['random_forest', 'gradient_boosting', 'xgboost']:
    classifier = CauseClassifier(model_type=model_type)
    stats = classifier.train(X_train, y_train)
    print(f"{model_type}: {stats['train_accuracy']:.4f}")
```

## Integration with Collector

Connect the detector directly to collector output:

```python
import subprocess
import csv
from realtime_detector import RealtimeDetector

detector = RealtimeDetector(
    anomaly_model_path='ml_model/anomaly_detector.pkl',
    cause_model_path='ml_model/cause_classifier.pkl'
)

# Read from collector output
with open('ebpf_logs/ebpf_events.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        event = {
            'pid': int(row['pid']),
            'latency_ns': int(row['latency_ns']),
            'ts_ns': int(row['ts_ns']),
            'cpu_id': int(row['cpu_id']),
            'priority': int(row['priority']),
            'comm': row['comm'],
        }
        detector.add_event(event)
        
        # Check for anomalies periodically
        if len(detector.events_buffer) % 100 == 0:
            result = detector.full_detection()
            if result.get('alert'):
                print(result['alert_message'])
```

## License

See parent project LICENSE

## References

- Isolation Forest: Liu et al., "Isolation Forest" (2008)
- Random Forest: Breiman, "Random Forests" (2001)
- XGBoost: Chen & Guestrin, "XGBoost: Scalable Tree Boosting" (2016)
