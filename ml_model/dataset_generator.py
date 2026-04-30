"""
Dataset Generator for Scheduling Latency Anomaly Detection
Converts raw eBPF collected events into ML-ready features
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple
import json


class DatasetGenerator:
    """Generate ML training dataset from raw collector events"""
    
    # Workload labels mapping
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
        'anomaly': 9  # For unclassified anomalies
    }
    
    LABEL_TO_NAME = {v: k for k, v in WORKLOAD_LABELS.items()}
    
    def __init__(self, window_size_ms: int = 100, stride_ms: int = 50):
        """
        Initialize dataset generator
        
        Args:
            window_size_ms: Time window for feature aggregation (milliseconds)
            stride_ms: Stride for sliding window (milliseconds)
        """
        self.window_size_ns = window_size_ms * 1_000_000  # Convert to nanoseconds
        self.stride_ns = stride_ms * 1_000_000
        
    def load_events(self, csv_path: str) -> pd.DataFrame:
        """Load raw events from collector CSV.

        Supports two formats:
        1. Raw event-level CSV with columns: `latency_ns, ts_ns, pid, cpu_id, priority, comm` (per-event)
        2. Supervised/aggregated CSV with columns:
           `timestamp, switch_count, avg_lat, min_lat, max_lat, p95_lat, p99_lat, stddev_lat,
            over20, over50, over100, avg_prio, highest_prio, label`

        If the file matches the supervised format, returns a DataFrame ready for training
        (feature columns mapped). Otherwise returns raw events DataFrame.
        """
        df = pd.read_csv(csv_path)

        # ── Normalise column names to internal convention ──────────────────────
        # The live eBPF collector writes:  timestamp_ns, latency_us, pid, tgid, comm, cpu_id, priority, label
        # The older/test format uses:      ts_ns, latency_ns, pid, cpu_id, priority, comm
        # We normalise everything to the internal convention ts_ns / latency_ns.
        rename_map = {}
        if 'timestamp_ns' in df.columns and 'ts_ns' not in df.columns:
            rename_map['timestamp_ns'] = 'ts_ns'
        if 'latency_us' in df.columns and 'latency_ns' not in df.columns:
            rename_map['latency_us'] = 'latency_ns'
            # latency_us -> latency_ns: multiply by 1000 after rename
        if 'tgid' in df.columns and 'pid' not in df.columns:
            rename_map['tgid'] = 'pid'
        if rename_map:
            df = df.rename(columns=rename_map)
        # If we renamed latency_us -> latency_ns, the values are still in us; convert.
        if 'latency_us' in rename_map:
            df['latency_ns'] = df['latency_ns'] * 1000.0

        # Detect supervised/aggregated format
        supervised_cols = {'timestamp', 'switch_count', 'avg_lat', 'min_lat', 'max_lat',
                           'p95_lat', 'p99_lat', 'stddev_lat', 'over20', 'over50', 'over100',
                           'avg_prio', 'highest_prio', 'label'}

        if supervised_cols.issubset(set(df.columns)):
            return self._load_supervised_aggregated(df)

        # Otherwise expect raw events format
        required_cols = ['latency_ns', 'ts_ns', 'pid', 'cpu_id', 'priority', 'comm']
        missing = [col for col in required_cols if col not in df.columns]
        if missing:
            raise ValueError(f"Missing columns in CSV: {missing}")

        # Convert to numeric types
        df['latency_ns'] = pd.to_numeric(df['latency_ns'], errors='coerce')
        df['ts_ns'] = pd.to_numeric(df['ts_ns'], errors='coerce')
        df['cpu_id'] = pd.to_numeric(df['cpu_id'], errors='coerce')
        df['priority'] = pd.to_numeric(df['priority'], errors='coerce')

        # Remove NaN rows
        df = df.dropna(subset=['latency_ns', 'ts_ns'])
        df = df.sort_values('ts_ns').reset_index(drop=True)

        return df

    def _load_supervised_aggregated(self, df: pd.DataFrame) -> pd.DataFrame:
        """Map supervised/aggregated collector CSV to ML feature columns.

        Expected input columns: timestamp, switch_count, avg_lat, min_lat, max_lat,
        p95_lat, p99_lat, stddev_lat, over20, over50, over100, avg_prio, highest_prio, label

        Returns DataFrame with feature columns compatible with the rest of the pipeline.
        """
        df = df.copy()

        # Drop columns not used by training or that may leak information
        for drop_col in ("target_tgid", "tgid", "highest_prio"):
            if drop_col in df.columns:
                df = df.drop(columns=[drop_col])

        # Normalize timestamp: allow numeric epoch or ISO string
        if 'timestamp' in df.columns:
            try:
                # If numeric (seconds or ns), keep as numeric
                df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
            except Exception:
                # Try parsing as datetimes and convert to epoch seconds
                try:
                    df['timestamp'] = pd.to_datetime(df['timestamp']).astype('int64') // 10**9
                except Exception:
                    pass

        # Map columns to expected feature names
        mapping = {
            'avg_lat': 'latency_mean',
            'stddev_lat': 'latency_std',
            'min_lat': 'latency_min',
            'max_lat': 'latency_max',
            'p95_lat': 'latency_p95',
            'p99_lat': 'latency_p99',
            'timestamp': 'window_start_ts',
            'avg_prio': 'priority_mean',
            'switch_count': 'event_count',
        }

        df = df.rename(columns=mapping)

        # Derive additional features if missing
        if 'latency_p50' not in df.columns and 'latency_mean' in df.columns:
            df['latency_p50'] = df['latency_mean']

        # If p75/p90/p95/p99 not present, approximate from p95/p99
        if 'latency_p75' not in df.columns:
            df['latency_p75'] = df.get('latency_p95', df.get('latency_mean'))
        if 'latency_p90' not in df.columns:
            df['latency_p90'] = df.get('latency_p95', df.get('latency_mean'))
        if 'latency_p99' not in df.columns:
            # already mapped above if present
            df['latency_p99'] = df.get('latency_p99', df.get('latency_max'))

        # Derive tail ratios from over20/over50/over100 if switch_count provided
        for col, name in [('over20', 'over20_ratio'), ('over50', 'over50_ratio'), ('over100', 'over100_ratio')]:
            if col in df.columns:
                df[name] = df[col] / df['event_count'].replace({0: np.nan})
            else:
                df[name] = 0.0

        # time span unknown for aggregated CSV; set to 0
        df['time_span_ns'] = 0

        # num_unique_cpus and cpu_concentration unknown -> set defaults
        df['num_unique_cpus'] = 1
        df['cpu_concentration'] = 1.0

        # Priority std/min if missing
        if 'priority_std' not in df.columns:
            df['priority_std'] = 0.0
        if 'priority_min' not in df.columns:
            df['priority_min'] = df.get('priority_mean', 0.0)

        # Latency distribution stats: skewness/kurtosis/median_abs_dev set to 0 if missing
        for stat in ['latency_skewness', 'latency_kurtosis', 'latency_median_abs_dev']:
            if stat not in df.columns:
                df[stat] = 0.0

        # Tail latency indicator for pipeline: use over100_ratio if available
        if 'over100_ratio' in df.columns:
            df['tail_latency_ratio'] = df['over100_ratio']
        else:
            df['tail_latency_ratio'] = 0.0

        # Ensure label column exists and is integer
        df['label'] = pd.to_numeric(df['label'], errors='coerce').fillna(-1).astype(int)

        # Keep only feature columns used by downstream code plus label and window timestamps
        feature_cols = [
            'latency_mean', 'latency_std', 'latency_min', 'latency_max',
            'latency_p50', 'latency_p75', 'latency_p90', 'latency_p95', 'latency_p99',
            'latency_skewness', 'latency_kurtosis', 'latency_median_abs_dev',
            'event_count', 'event_rate', 'time_span_ns',
            'num_unique_cpus', 'cpu_concentration',
            'priority_mean', 'priority_std', 'priority_min',
            'outlier_ratio_3sigma', 'tail_latency_ratio'
        ]

        # Populate missing columns with defaults
        for col in feature_cols:
            if col not in df.columns:
                df[col] = 0.0

        # event_rate/from switch_count: assume event_count per second unknown -> set 0
        if 'event_rate' not in df.columns:
            df['event_rate'] = 0.0

        # window timestamps
        if 'window_start_ts' not in df.columns:
            df['window_start_ts'] = pd.to_datetime(df.get('window_start_ts', pd.Series([0]*len(df))))
        df['window_end_ts'] = df['window_start_ts']

        # Reorder columns to be consistent
        out_df = df[feature_cols + ['label', 'window_start_ts', 'window_end_ts']]
        return out_df.reset_index(drop=True)
    
    def extract_window_features(self, events: pd.DataFrame) -> Dict[str, float]:
        """
        Extract statistical features from a time window of events
        
        Features:
        - Latency statistics: mean, std, min, max, p50, p75, p90, p95, p99
        - Latency distribution: skewness, kurtosis
        - Temporal: event rate, time span
        - CPU distribution: num_unique_cpus, cpu_concentration
        - Priority stats: mean priority, priority variance
        """
        if len(events) == 0:
            return self._get_empty_features()
        
        latencies = events['latency_ns'].values
        
        features = {
            # Latency statistics
            'latency_mean': float(np.mean(latencies)),
            'latency_std': float(np.std(latencies)),
            'latency_min': float(np.min(latencies)),
            'latency_max': float(np.max(latencies)),
            'latency_p50': float(np.percentile(latencies, 50)),
            'latency_p75': float(np.percentile(latencies, 75)),
            'latency_p90': float(np.percentile(latencies, 90)),
            'latency_p95': float(np.percentile(latencies, 95)),
            'latency_p99': float(np.percentile(latencies, 99)),
            
            # Distribution shape
            'latency_skewness': float(pd.Series(latencies).skew()),
            'latency_kurtosis': float(pd.Series(latencies).kurtosis()),
            'latency_median_abs_dev': float(np.median(np.abs(latencies - np.median(latencies)))),
            
            # Temporal features
            'event_count': len(events),
            'event_rate': len(events) / max(1, (events['ts_ns'].max() - events['ts_ns'].min()) / 1e9),
            'time_span_ns': float(events['ts_ns'].max() - events['ts_ns'].min()),
            
            # CPU distribution
            'num_unique_cpus': events['cpu_id'].nunique(),
            'cpu_concentration': float(events['cpu_id'].value_counts().max() / len(events)),
            
            # Priority statistics
            'priority_mean': float(events['priority'].mean()),
            'priority_std': float(events['priority'].std()),
            'priority_min': float(events['priority'].min()),
            'priority_max': float(events['priority'].max()),
            
            # Tail latency indicators (anomaly features)
            'outlier_ratio_3sigma': float(np.sum(np.abs(latencies - np.mean(latencies)) > 3 * np.std(latencies)) / len(latencies)),
            'tail_latency_ratio': float(np.sum(latencies > np.percentile(latencies, 95)) / len(latencies)),
        }
        
        return features
    
    def _get_empty_features(self) -> Dict[str, float]:
        """Return empty feature dict with all features set to 0"""
        return {
            'latency_mean': 0.0,
            'latency_std': 0.0,
            'latency_min': 0.0,
            'latency_max': 0.0,
            'latency_p50': 0.0,
            'latency_p75': 0.0,
            'latency_p90': 0.0,
            'latency_p95': 0.0,
            'latency_p99': 0.0,
            'latency_skewness': 0.0,
            'latency_kurtosis': 0.0,
            'latency_median_abs_dev': 0.0,
            'event_count': 0.0,
            'event_rate': 0.0,
            'time_span_ns': 0.0,
            'num_unique_cpus': 0.0,
            'cpu_concentration': 0.0,
            'priority_mean': 0.0,
            'priority_std': 0.0,
            'priority_min': 0.0,
            'priority_max': 0.0,
            'outlier_ratio_3sigma': 0.0,
            'tail_latency_ratio': 0.0,
        }
    
    def generate_dataset(self, csv_path: str, label: int = None) -> pd.DataFrame:
        """
        Generate ML dataset from raw events using sliding window approach
        
        Args:
            csv_path: Path to events CSV file
            label: Workload label (0-9). If None, will try to extract from filename
            
        Returns:
            DataFrame with features and label for each time window
        """
        events_df = self.load_events(csv_path)

        # If load_events returned an aggregated supervised DataFrame (features + label), return it directly
        if 'label' in events_df.columns and 'latency_mean' in events_df.columns:
            # If caller passed an explicit label, override the label column
            if label is not None:
                events_df['label'] = int(label)
            return events_df.reset_index(drop=True)

        if label is None:
            # Try to infer label from filename
            filename = Path(csv_path).stem.lower()
            label = self._infer_label(filename)
            if label is None:
                raise ValueError(f"Could not infer label from {csv_path}. Specify label explicitly.")

        # Generate sliding windows from raw events
        dataset_rows = []

        if len(events_df) == 0:
            return pd.DataFrame()

        min_ts = events_df['ts_ns'].min()
        max_ts = events_df['ts_ns'].max()

        current_ts = min_ts
        while current_ts + self.window_size_ns <= max_ts:
            window_end = current_ts + self.window_size_ns

            # Get events in this window
            window_events = events_df[
                (events_df['ts_ns'] >= current_ts) & 
                (events_df['ts_ns'] < window_end)
            ]

            if len(window_events) > 0:
                features = self.extract_window_features(window_events)
                features['label'] = label
                features['window_start_ts'] = current_ts
                features['window_end_ts'] = window_end
                dataset_rows.append(features)

            current_ts += self.stride_ns

        dataset_df = pd.DataFrame(dataset_rows)
        return dataset_df
    
    def _infer_label(self, filename: str) -> int:
        """Try to infer workload label from filename"""
        for label_name, label_id in self.WORKLOAD_LABELS.items():
            if label_name.lower() in filename.lower():
                return label_id
        return None
    
    def combine_datasets(self, dataset_paths: List[Tuple[str, int]]) -> pd.DataFrame:
        """
        Combine multiple datasets with their labels
        
        Args:
            dataset_paths: List of (csv_path, label) tuples
            
        Returns:
            Combined DataFrame with all samples
        """
        all_data = []
        
        for csv_path, label in dataset_paths:
            print(f"Processing {csv_path} with label {label} ({self.LABEL_TO_NAME.get(label, 'unknown')})")
            dataset = self.generate_dataset(csv_path, label)
            all_data.append(dataset)
        
        combined_df = pd.concat(all_data, ignore_index=True)
        print(f"Combined dataset shape: {combined_df.shape}")
        print(f"Label distribution:\n{combined_df['label'].value_counts().sort_index()}")
        
        return combined_df
    
    def save_dataset(self, df: pd.DataFrame, output_path: str):
        """Save dataset to CSV"""
        df.to_csv(output_path, index=False)
        print(f"Dataset saved to {output_path}")
    
    def split_train_test(self, df: pd.DataFrame, test_ratio: float = 0.2, 
                         random_state: int = 42) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Split dataset into train/test sets while preserving label distribution"""
        from sklearn.model_selection import train_test_split
        
        features = [
            col for col in df.columns
            if col not in ['label', 'timestamp', 'ts_ns', 'window_start_ts', 'window_end_ts']
        ]
        
        X = df[features]
        y = df['label']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_ratio, random_state=random_state, stratify=y
        )
        
        train_df = X_train.copy()
        train_df['label'] = y_train.values
        
        test_df = X_test.copy()
        test_df['label'] = y_test.values
        
        return train_df, test_df


def create_example_usage():
    """Example usage of DatasetGenerator"""
    
    gen = DatasetGenerator(window_size_ms=100, stride_ms=50)
    
    # Example: combine multiple workload recordings
    # dataset_paths = [
    #     ('ebpf_logs/baseline_events.csv', 0),
    #     ('ebpf_logs/cpu_contention_events.csv', 1),
    #     ('ebpf_logs/disk_io_events.csv', 3),
    # ]
    # combined_df = gen.combine_datasets(dataset_paths)
    # gen.save_dataset(combined_df, 'ml_model/training_dataset.csv')


if __name__ == "__main__":
    create_example_usage()