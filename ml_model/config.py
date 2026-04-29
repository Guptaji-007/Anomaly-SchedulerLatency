"""
Configuration for ML Anomaly Detection Pipeline
Centralized configuration for all components
"""

import json
from pathlib import Path
from typing import Dict, Any


class Config:
    """ML Pipeline Configuration"""
    
    # Dataset Configuration
    WINDOW_SIZE_MS = 100        # Feature extraction window (milliseconds)
    STRIDE_MS = 50              # Sliding window stride (milliseconds)
    
    # Anomaly Detection Configuration
    ANOMALY_CONTAMINATION = 0.1  # Expected fraction of anomalies
    ANOMALY_N_ESTIMATORS = 100   # Number of trees in Isolation Forest
    
    # Cause Classification Configuration
    CLASSIFIER_MODEL_TYPE = 'random_forest'  # 'random_forest', 'gradient_boosting', 'xgboost'
    CLASSIFIER_N_ESTIMATORS = 100
    CLASSIFIER_MAX_DEPTH = 15
    CLASSIFIER_MIN_SAMPLES_SPLIT = 5
    CLASSIFIER_TEST_SIZE = 0.2
    
    # Real-time Detection Configuration
    REALTIME_BUFFER_SIZE = 10000
    REALTIME_ALERT_THRESHOLD = 0.7
    REALTIME_MONITORING_INTERVAL_SEC = 1.0
    
    # Paths
    MODEL_DIR = 'ml_model'
    ANOMALY_MODEL_PATH = 'ml_model/anomaly_detector.pkl'
    CAUSE_MODEL_PATH = 'ml_model/cause_classifier.pkl'
    DATASET_PATH = 'ml_model/training_dataset.csv'
    LOG_PATH = 'ml_model/detection_results.jsonl'
    CONFIG_PATH = 'ml_model/config.json'
    
    # Workload Labels
    WORKLOAD_LABELS = {
        'baseline': 0,
        'cpu_contention': 1,
        'heavy_contention': 2,
        'disk_io': 3,
        'memory_pressure': 4,
        'lock_contention': 5,
        'ipc_communication': 6,
        'context_switching': 7,
        'mixed': 8,
        'anomaly': 9,
    }
    
    LABEL_TO_NAME = {v: k for k, v in WORKLOAD_LABELS.items()}
    
    # Feature names (in order of extraction)
    FEATURE_NAMES = [
        'latency_mean',
        'latency_std',
        'latency_min',
        'latency_max',
        'latency_p50',
        'latency_p75',
        'latency_p90',
        'latency_p95',
        'latency_p99',
        'latency_skewness',
        'latency_kurtosis',
        'latency_median_abs_dev',
        'event_count',
        'event_rate',
        'time_span_ns',
        'num_unique_cpus',
        'cpu_concentration',
        'priority_mean',
        'priority_std',
        'priority_min',
        'priority_max',
        'outlier_ratio_3sigma',
        'tail_latency_ratio',
    ]
    
    # Collector Configuration
    COLLECTOR_BIN = 'ebpf_logs/collector'
    COLLECTOR_MIN_LATENCY_US = 1000
    COLLECTOR_SAMPLE_RATE = 1
    
    # Training Configuration
    TRAINING_CV_FOLDS = 5
    TRAINING_RANDOM_STATE = 42
    TRAINING_N_JOBS = -1  # Use all CPU cores
    
    @classmethod
    def to_dict(cls) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return {
            'window_size_ms': cls.WINDOW_SIZE_MS,
            'stride_ms': cls.STRIDE_MS,
            'anomaly_contamination': cls.ANOMALY_CONTAMINATION,
            'classifier_model_type': cls.CLASSIFIER_MODEL_TYPE,
            'classifier_test_size': cls.CLASSIFIER_TEST_SIZE,
            'alert_threshold': cls.REALTIME_ALERT_THRESHOLD,
            'workload_labels': cls.WORKLOAD_LABELS,
            'feature_names': cls.FEATURE_NAMES,
            'model_paths': {
                'anomaly_model': cls.ANOMALY_MODEL_PATH,
                'cause_model': cls.CAUSE_MODEL_PATH,
                'dataset': cls.DATASET_PATH,
                'log': cls.LOG_PATH,
            }
        }
    
    @classmethod
    def from_json(cls, json_path: str) -> 'Config':
        """Load configuration from JSON file"""
        with open(json_path, 'r') as f:
            config_dict = json.load(f)
        
        # Update class attributes
        for key, value in config_dict.items():
            attr_name = key.upper()
            if hasattr(cls, attr_name):
                setattr(cls, attr_name, value)
        
        return cls
    
    @classmethod
    def save_json(cls, json_path: str = None):
        """Save configuration to JSON file"""
        if json_path is None:
            json_path = cls.CONFIG_PATH
        
        Path(json_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(json_path, 'w') as f:
            json.dump(cls.to_dict(), f, indent=2)
        
        print(f"Configuration saved to {json_path}")
    
    @classmethod
    def print_config(cls):
        """Print configuration"""
        print("\n" + "="*60)
        print("ML PIPELINE CONFIGURATION")
        print("="*60)
        
        print("\nDataset Configuration:")
        print(f"  Window size: {cls.WINDOW_SIZE_MS} ms")
        print(f"  Stride: {cls.STRIDE_MS} ms")
        print(f"  Number of features: {len(cls.FEATURE_NAMES)}")
        
        print("\nAnomaly Detection:")
        print(f"  Contamination: {cls.ANOMALY_CONTAMINATION}")
        print(f"  Estimators: {cls.ANOMALY_N_ESTIMATORS}")
        
        print("\nCause Classification:")
        print(f"  Model type: {cls.CLASSIFIER_MODEL_TYPE}")
        print(f"  Test size: {cls.CLASSIFIER_TEST_SIZE}")
        print(f"  Max depth: {cls.CLASSIFIER_MAX_DEPTH}")
        
        print("\nReal-time Detection:")
        print(f"  Buffer size: {cls.REALTIME_BUFFER_SIZE}")
        print(f"  Alert threshold: {cls.REALTIME_ALERT_THRESHOLD}")
        
        print("\nWorkload Labels:")
        for name, label_id in sorted(cls.WORKLOAD_LABELS.items()):
            if label_id < 9:  # Don't show 'anomaly' label
                print(f"  {label_id}: {name}")


# Global config instance
_config = Config()


def get_config() -> Config:
    """Get global configuration instance"""
    return _config


def update_config(**kwargs):
    """Update configuration parameters"""
    for key, value in kwargs.items():
        attr_name = key.upper()
        if hasattr(Config, attr_name):
            setattr(Config, attr_name, value)
        else:
            print(f"Warning: Unknown config parameter {key}")


if __name__ == "__main__":
    Config.print_config()
