#!/usr/bin/env python3
"""
===================================================================
EXPLAIN SPIKES - Predict Latency Spike Causes
===================================================================
Uses trained XGBoost model to explain why latency spikes occur
"""

import numpy as np
import json
import sys
from pathlib import Path
import joblib

class SpikeCauseExplainer:
    def __init__(self, model_path=None, scaler_path=None, encoder_path=None):
        """Initialize explainer with trained model"""
        self.script_dir = Path(__file__).parent.absolute()
        self.ebpf_dir = self.script_dir / "ebpf_logs"
        
        # Default paths
        if model_path is None:
            model_path = self.ebpf_dir / "cause_classifier_xgboost.pkl"
        if scaler_path is None:
            scaler_path = self.ebpf_dir / "cause_scaler.pkl"
        if encoder_path is None:
            encoder_path = self.ebpf_dir / "cause_encoder.pkl"
        
        self.model_path = Path(model_path)
        self.scaler_path = Path(scaler_path)
        self.encoder_path = Path(encoder_path)
        
        self.model = None
        self.scaler = None
        self.encoder = None
        self.metadata = None
        
        self.load_models()
    
    def load_models(self):
        """Load trained model and components"""
        print("Loading trained model...\n")
        
        # Check files exist
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found: {self.model_path}\n"
                                  "Train it first: python3 train_cause_classifier.py")
        if not self.scaler_path.exists():
            raise FileNotFoundError(f"Scaler not found: {self.scaler_path}")
        if not self.encoder_path.exists():
            raise FileNotFoundError(f"Encoder not found: {self.encoder_path}")
        
        # Load
        self.model = joblib.load(self.model_path)
        self.scaler = joblib.load(self.scaler_path)
        self.encoder = joblib.load(self.encoder_path)
        
        # Load metadata
        metadata_path = self.ebpf_dir / "cause_metadata.json"
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                self.metadata = json.load(f)
        
        print(f"✓ Model loaded: {self.model_path}")
        print(f"✓ Scaler loaded")
        print(f"✓ Encoder loaded")
        if self.metadata:
            print(f"✓ Metadata loaded")
        print()
    
    # ===================================================================
    # FEATURE EXTRACTION
    # ===================================================================
    
    def extract_features(self, latency_us):
        """Extract features from single latency value"""
        features = []
        
        # Feature 1: Raw latency
        features.append(latency_us)
        
        # Feature 2: Log latency
        features.append(np.log1p(latency_us))
        
        # Feature 3: Squared latency
        features.append((latency_us ** 2) / 1e6)
        
        # Feature 4: Latency bin (simplified - use percentile)
        # Assume ranges 0-100, 100-500, 500-1000, 1000-2000, 2000+
        if latency_us < 100:
            bin_val = 0
        elif latency_us < 500:
            bin_val = 1
        elif latency_us < 1000:
            bin_val = 2
        elif latency_us < 2000:
            bin_val = 3
        else:
            bin_val = 4
        features.append(float(bin_val))
        
        # Feature 5: Normalized latency (rough estimate)
        # Assume range 50-5000
        normalized = (latency_us - 50) / (5000 - 50)
        normalized = max(0, min(1, normalized))
        features.append(normalized)
        
        return np.array([features])
    
    # ===================================================================
    # SPIKE DETECTION
    # ===================================================================
    
    def is_spike(self, latency_us, threshold_us=500):
        """Check if latency is considered a spike"""
        return latency_us > threshold_us
    
    # ===================================================================
    # CAUSE EXPLANATION
    # ===================================================================
    
    def explain(self, latency_us, threshold_us=500):
        """Explain the cause of a latency spike"""
        # Extract features
        X = self.extract_features(latency_us)
        
        # Scale
        X_scaled = self.scaler.transform(X)
        
        # Predict
        prediction = self.model.predict(X_scaled)[0]
        predicted_cause = self.encoder.inverse_transform([prediction])[0]
        
        # Get probabilities
        if hasattr(self.model, 'predict_proba'):
            probabilities = self.model.predict_proba(X_scaled)[0]
        else:
            # For models without predict_proba
            probabilities = None
        
        # Is it a spike?
        spike = self.is_spike(latency_us, threshold_us)
        
        # Confidence
        if probabilities is not None:
            confidence = float(np.max(probabilities))
        else:
            confidence = 1.0
        
        # Build result
        result = {
            'latency_us': latency_us,
            'is_spike': spike,
            'spike_threshold_us': threshold_us,
            'predicted_cause': predicted_cause,
            'confidence': confidence,
            'confidence_percent': f"{confidence*100:.1f}%"
        }
        
        # Add per-cause probabilities
        if probabilities is not None:
            prob_dict = {}
            for i, cause in enumerate(self.encoder.classes_):
                prob_dict[cause] = float(probabilities[i])
            
            # Sort by probability
            sorted_probs = sorted(prob_dict.items(), key=lambda x: x[1], reverse=True)
            result['probability'] = {cause: prob for cause, prob in sorted_probs}
        
        # Add metadata if available
        if self.metadata:
            result['model_info'] = {
                'model_type': self.metadata['model_type'],
                'test_accuracy': self.metadata['test_accuracy'],
                'trained_at': self.metadata['trained_at']
            }
        
        return result
    
    # ===================================================================
    # VISUALIZATION
    # ===================================================================
    
    def print_result(self, result):
        """Pretty print explanation"""
        latency = result['latency_us']
        cause = result['predicted_cause']
        confidence = result['confidence']
        is_spike = result['is_spike']
        
        print(f"╔═══════════════════════════════════════════════╗")
        print(f"║         LATENCY SPIKE EXPLANATION            ║")
        print(f"╚═══════════════════════════════════════════════╝")
        print()
        
        print(f"Input Latency: {latency:.2f} µs")
        print(f"Is Spike:      {('YES' if is_spike else 'NO'):>4} (threshold: {result['spike_threshold_us']} µs)")
        print()
        
        print(f"Predicted Cause: {cause}")
        print(f"Confidence:      {confidence:.1%}")
        print()
        
        if 'probability' in result:
            print("Cause probabilities:")
            for cause_name, prob in result['probability'].items():
                bar = "█" * int(prob * 30)
                print(f"  {cause_name:30s} {prob:6.1%} {bar}")
        
        if 'model_info' in result:
            print()
            print(f"Model: {result['model_info']['model_type']}")
            print(f"Accuracy: {result['model_info']['test_accuracy']:.1%}")
        
        print()
    
    # ===================================================================
    # INTERACTIVE DEMO
    # ===================================================================
    
    def interactive_demo(self):
        """Interactive spike explanation demo"""
        print("╔═══════════════════════════════════════════════╗")
        print("║      INTERACTIVE SPIKE CAUSE EXPLAINER       ║")
        print("║                                               ║")
        print("║  Enter latency values to see predicted cause  ║")
        print("║  Type 'quit' to exit                         ║")
        print("║  Type 'demo' to see sample spikes            ║")
        print("╚═══════════════════════════════════════════════╝")
        print()
        
        # Demo samples
        demo_samples = {
            'demo': [
                ('baseline', 150),
                ('cpu_contention', 800),
                ('heavy_contention', 3000),
                ('disk_io', 2000),
                ('memory_pressure', 1200),
                ('lock_contention', 1500),
                ('ipc_communication', 800),
                ('context_switching', 600),
                ('mixed', 1800),
            ]
        }
        
        while True:
            try:
                user_input = input("Enter latency (µs) or 'demo' or 'quit': ").strip().lower()
                
                if user_input == 'quit':
                    print("Goodbye!")
                    break
                
                elif user_input == 'demo':
                    print("\n" + "="*60)
                    print("DEMO: Sample latencies from each workload type")
                    print("="*60 + "\n")
                    
                    for cause, latency in demo_samples['demo']:
                        print(f"Sample: {cause} → {latency} µs")
                        result = self.explain(latency)
                        print(f"  Predicted: {result['predicted_cause']} ({result['confidence']:.1%})")
                        print()
                
                else:
                    try:
                        latency = float(user_input)
                        print()
                        result = self.explain(latency)
                        self.print_result(result)
                    except ValueError:
                        print("Invalid input. Enter a number, 'demo', or 'quit'")
            
            except KeyboardInterrupt:
                print("\n\nInterrupted. Goodbye!")
                break
            except Exception as e:
                print(f"Error: {e}")
    
    # ===================================================================
    # TEST SUITE
    # ===================================================================
    
    def run_tests(self):
        """Run test predictions on sample data"""
        print("╔═══════════════════════════════════════════════╗")
        print("║         RUNNING TEST PREDICTIONS             ║")
        print("╚═══════════════════════════════════════════════╝")
        print()
        
        # Test cases: latency_us, expected_range
        test_cases = [
            ("Baseline", 120, "baseline", 100, 200),
            ("CPU Contention", 800, "cpu_contention", 300, 1500),
            ("Heavy Contention", 3500, "heavy_contention", 800, 5000),
            ("Disk I/O", 1800, "disk_io", 100, 4000),
            ("Memory Pressure", 900, "memory_pressure", 400, 2000),
            ("Lock Contention", 1200, "lock_contention", 500, 2500),
            ("IPC", 600, "ipc_communication", 350, 1800),
            ("Context Switching", 500, "context_switching", 250, 1500),
            ("Mixed", 1500, "mixed", 100, 3000),
        ]
        
        correct = 0
        
        for name, latency, expected_cause, min_lat, max_lat in test_cases:
            result = self.explain(latency)
            predicted = result['predicted_cause']
            confidence = result['confidence']
            
            # Check if prediction is correct
            is_correct = predicted == expected_cause
            if is_correct:
                correct += 1
                status = "✓"
            else:
                status = "✗"
            
            print(f"{status} {name:25s} {latency:6.0f}µs → {predicted:30s} ({confidence:5.1%})")
        
        accuracy = 100 * correct / len(test_cases)
        print()
        print(f"Test Accuracy: {correct}/{len(test_cases)} ({accuracy:.1f}%)")
        print()

# ===================================================================
# MAIN
# ===================================================================

if __name__ == "__main__":
    try:
        explainer = SpikeCauseExplainer()
        
        # Run tests first
        explainer.run_tests()
        
        # Then interactive demo
        print("\n")
        explainer.interactive_demo()
        
    except FileNotFoundError as e:
        print(f"\n✗ {e}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
