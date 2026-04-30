"""
Real-time Anomaly Detection and Cause Classification
Integrates with collector to detect anomalies in real-time
"""

try:
    import pandas as pd
    import numpy as np
except Exception:
    pd = None  # type: ignore
    np = None  # type: ignore
from typing import Any, Dict, List, Optional, Tuple
from collections import deque
from datetime import datetime
import json
import threading
import time

# Don't import heavy trainer classes at module import time; import lazily inside __init__
# Delay importing DatasetGenerator (it requires pandas) until runtime to avoid
# import-time failures when the environment doesn't have optional heavy deps.


class RealtimeDetector:
    """Real-time anomaly detection engine"""
    
    def __init__(self, anomaly_model_path: str = None, cause_model_path: str = None,
                 window_size_ms: int = 100, alert_threshold: float = 0.7):
        """
        Initialize real-time detector
        
        Args:
            anomaly_model_path: Path to saved anomaly detector model
            cause_model_path: Path to saved cause classifier model
            window_size_ms: Feature extraction window size
            alert_threshold: Confidence threshold for alerts
        """
        self.anomaly_detector = None
        self.cause_classifier = None
        # DatasetGenerator is imported lazily to avoid requiring pandas at import time
        try:
            from ml_model.dataset_generator import DatasetGenerator  # type: ignore
        except Exception:
            # If import fails, keep dataset_gen as None and surface errors when used.
            DatasetGenerator = None  # type: ignore
        if DatasetGenerator is not None:
            self.dataset_gen = DatasetGenerator(window_size_ms=window_size_ms, stride_ms=window_size_ms)
        else:
            self.dataset_gen = None
        self.alert_threshold = alert_threshold
        
        # Load models if provided (import trainer classes lazily)
        if anomaly_model_path:
            try:
                from ml_model.model_trainer import AnomalyDetector  # type: ignore
            except Exception as e:
                raise RuntimeError(f"Could not import AnomalyDetector: {e}")
            self.anomaly_detector = AnomalyDetector()
            self.anomaly_detector.load(anomaly_model_path)

        if cause_model_path:
            try:
                from ml_model.model_trainer import CauseClassifier  # type: ignore
            except Exception as e:
                raise RuntimeError(f"Could not import CauseClassifier: {e}")
            self.cause_classifier = CauseClassifier()
            self.cause_classifier.load(cause_model_path)
        
        # Circular buffer for events
        self.events_buffer = deque(maxlen=10000)
        self.lock = threading.Lock()
        self.is_running = False
        
    def add_event(self, event: Dict):
        """Add a raw event from collector"""
        with self.lock:
            self.events_buffer.append(event)
    
    def add_events_batch(self, events: List[Dict]):
        """Add multiple events"""
        with self.lock:
            self.events_buffer.extend(events)
    
    def _get_recent_window(self, window_size_ns: int = None) -> Any:
        """Get recent events within window"""
        if window_size_ns is None:
            window_size_ns = self.dataset_gen.window_size_ns
        
        if len(self.events_buffer) == 0:
            # If pandas is unavailable return an empty list-convertible object
            if pd is None:
                return []
            return pd.DataFrame()
        
        with self.lock:
            events_list = list(self.events_buffer)
        
        if pd is None:
            # Cannot build DataFrame without pandas; return raw list
            return events_list
        df = pd.DataFrame(events_list)
        if df.empty:
            return df
        
        # Get events from last window
        max_ts = df['ts_ns'].max()
        min_ts = max_ts - window_size_ns
        
        return df[df['ts_ns'] >= min_ts]
    
    def detect_anomaly(self) -> Optional[Dict]:
        """
        Detect anomalies in recent window
        
        Returns:
            Detection result with anomaly score and details
        """
        if self.anomaly_detector is None:
            return None
        
        window_events = self._get_recent_window()
        if len(window_events) < 5:
            return None
        
        # Extract features
        if self.dataset_gen is None:
            raise RuntimeError("DatasetGenerator not available; install pandas to enable ML detection.")
        features = self.dataset_gen.extract_window_features(window_events)
        feature_df = pd.DataFrame([features])
        
        # Get only the features used during training
        feature_df = feature_df[self.anomaly_detector.features]
        
        # Predict
        predictions, scores = self.anomaly_detector.predict(feature_df)
        
        is_anomaly = predictions[0] == -1
        anomaly_score = float(scores[0])
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'is_anomaly': is_anomaly,
            'anomaly_score': anomaly_score,
            'n_events': len(window_events),
            'latency_mean_ns': features['latency_mean'],
            'latency_p99_ns': features['latency_p99'],
            'latency_max_ns': features['latency_max'],
            'confidence': abs(anomaly_score) / (self.anomaly_detector.stats.get('anomaly_scores_max', 1.0))
        }
        
        return result
    
    def classify_cause(self) -> Optional[Dict]:
        """
        Classify cause of anomaly
        
        Returns:
            Classification result with cause and confidence
        """
        if self.cause_classifier is None:
            return None
        
        window_events = self._get_recent_window()
        if len(window_events) < 5:
            return None
        
        # Extract features
        if self.dataset_gen is None:
            raise RuntimeError("DatasetGenerator not available; install pandas to enable ML classification.")
        features = self.dataset_gen.extract_window_features(window_events)
        feature_df = pd.DataFrame([features])
        
        # Get only the features used during training
        feature_df = feature_df[self.cause_classifier.features]
        
        # Predict
        predictions, probabilities = self.cause_classifier.predict(feature_df)
        
        predicted_class = int(predictions[0])
        
        if probabilities is not None:
            class_probs = {
                DatasetGenerator.LABEL_TO_NAME.get(int(self.cause_classifier.classes[i]), f'class_{i}'): 
                float(probabilities[0, i])
                for i in range(len(self.cause_classifier.classes))
            }
            confidence = float(np.max(probabilities[0]))
        else:
            class_probs = {}
            confidence = None
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'predicted_cause': DatasetGenerator.LABEL_TO_NAME.get(predicted_class, f'unknown_{predicted_class}'),
            'predicted_class': predicted_class,
            'confidence': confidence,
            'all_probabilities': class_probs,
            'n_events': len(window_events),
        }
        
        return result
    
    def full_detection(self) -> Dict:
        """
        Perform full anomaly detection and cause classification
        
        Returns:
            Complete detection result
        """
        detection_result = self.detect_anomaly()
        classification_result = self.classify_cause()
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'anomaly_detection': detection_result,
            'cause_classification': classification_result,
        }
        
        if detection_result and detection_result['is_anomaly']:
            if classification_result and classification_result['confidence'] is not None:
                if classification_result['confidence'] >= self.alert_threshold:
                    result['alert'] = True
                    result['alert_message'] = (
                        f"ANOMALY DETECTED: {classification_result['predicted_cause']} "
                        f"(confidence: {classification_result['confidence']:.2%})"
                    )
        
        return result
    
    def start_monitoring(self, callback=None, interval_sec: float = 1.0):
        """
        Start background monitoring thread
        
        Args:
            callback: Function to call with detection results
            interval_sec: Detection interval
        """
        self.is_running = True
        
        def monitor_loop():
            while self.is_running:
                try:
                    result = self.full_detection()
                    
                    if callback:
                        callback(result)
                    
                    if 'alert' in result and result['alert']:
                        print(f"\n⚠️  {result['alert_message']}")
                    
                    time.sleep(interval_sec)
                
                except Exception as e:
                    print(f"Error in monitoring loop: {e}")
                    time.sleep(interval_sec)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        print("Monitoring started...")
        
        return monitor_thread
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.is_running = False
        print("Monitoring stopped")
    
    def get_buffer_stats(self) -> Dict:
        """Get statistics about the event buffer"""
        with self.lock:
            if len(self.events_buffer) == 0:
                return {'n_events': 0}
            
            events_list = list(self.events_buffer)
        
        df = pd.DataFrame(events_list)
        
        if df.empty:
            return {'n_events': 0}
        
        return {
            'n_events': len(df),
            'buffer_capacity': self.events_buffer.maxlen,
            'time_span_seconds': (df['ts_ns'].max() - df['ts_ns'].min()) / 1e9,
            'events_per_second': len(df) / max(1, (df['ts_ns'].max() - df['ts_ns'].min()) / 1e9),
        }


class DetectionLogger:
    """Log detection results for analysis"""
    
    def __init__(self, log_file: str = None):
        """
        Initialize logger
        
        Args:
            log_file: Path to log file
        """
        self.log_file = log_file or 'ml_model/detection_log.jsonl'
        self.detections = []
    
    def log_detection(self, result: Dict):
        """Log a detection result"""
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(result) + '\n')
        
        self.detections.append(result)
    
    def load_logs(self, limit: int = None) -> List[Dict]:
        """Load detection logs"""
        try:
            results = []
            with open(self.log_file, 'r') as f:
                for line in f:
                    results.append(json.loads(line))
                    if limit and len(results) >= limit:
                        break
            return results
        except FileNotFoundError:
            return []
    
    def get_anomaly_statistics(self) -> Dict:
        """Get statistics from logs"""
        logs = self.load_logs()
        if not logs:
            return {}
        
        # Extract anomaly detection results
        anomalies = [
            log['anomaly_detection'] for log in logs 
            if log.get('anomaly_detection') and log['anomaly_detection'].get('is_anomaly')
        ]
        
        if not anomalies:
            return {'total_anomalies': 0}
        
        # Extract cause classifications
        causes = {}
        for log in logs:
            if log.get('cause_classification') and log['cause_classification'].get('predicted_cause'):
                cause = log['cause_classification']['predicted_cause']
                causes[cause] = causes.get(cause, 0) + 1
        
        return {
            'total_detections': len(logs),
            'total_anomalies': len(anomalies),
            'anomaly_percentage': 100 * len(anomalies) / len(logs) if logs else 0,
            'average_anomaly_score': float(np.mean([a['anomaly_score'] for a in anomalies])) if anomalies else 0,
            'cause_distribution': causes,
        }


if __name__ == "__main__":
    print("Real-time detection module - import and use classes directly")
