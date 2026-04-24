#!/bin/bash
# ===================================================================
# COMPLETE PIPELINE RUNNER - End-to-End Linux Solution
# ===================================================================
# This script runs the ENTIRE pipeline:
# 1. Generate labeled dataset
# 2. Train ML classifier
# 3. Run inference demo
# ===================================================================

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

print_header() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  $1"
    echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
}

print_step() {
    echo -e "${GREEN}[STEP $1]${NC} $2"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# ===================================================================
# MAIN PIPELINE
# ===================================================================

main() {
    print_header "COMPLETE ML PIPELINE - LINUX"
    
    cd "$SCRIPT_DIR"
    
    # ===================================================================
    # PHASE 1: DATASET GENERATION
    # ===================================================================
    
    print_step "1" "DATASET GENERATION"
    echo ""
    echo "This will:"
    echo "  • Compile 9 workload types"
    echo "  • Run each with eBPF collector"
    echo "  • Generate labeled dataset CSV"
    echo ""
    
    if bash run_dataset_generation.sh; then
        print_success "Dataset generation complete"
    else
        print_error "Dataset generation failed"
        exit 1
    fi
    
    # ===================================================================
    # PHASE 2: VERIFY DATASET
    # ===================================================================
    
    print_step "2" "VERIFYING DATASET"
    
    DATASET="ebpf_logs/labeled_dataset.csv"
    
    if [ ! -f "$DATASET" ]; then
        print_error "Dataset file not found: $DATASET"
        exit 1
    fi
    
    SAMPLE_COUNT=$(($(wc -l < "$DATASET") - 1))
    echo "Dataset has $SAMPLE_COUNT samples"
    
    if [ $SAMPLE_COUNT -lt 100 ]; then
        print_error "Dataset too small (need at least 100 samples)"
        exit 1
    fi
    
    print_success "Dataset verified"
    
    # ===================================================================
    # PHASE 3: TRAIN CLASSIFIER
    # ===================================================================
    
    print_step "3" "TRAINING CLASSIFIER"
    echo ""
    echo "This will:"
    echo "  • Extract features from latencies"
    echo "  • Train 3 ML models"
    echo "  • Select best model (XGBoost)"
    echo ""
    
    if python3 train_cause_classifier.py; then
        print_success "Model training complete"
    else
        print_error "Model training failed"
        exit 1
    fi
    
    # ===================================================================
    # PHASE 4: TEST INFERENCE
    # ===================================================================
    
    print_step "4" "TESTING INFERENCE"
    echo ""
    echo "This will show real-time spike explanations"
    echo ""
    
    if python3 explain_spikes.py; then
        print_success "Inference test complete"
    else
        print_error "Inference test failed (but model may still be usable)"
    fi
    
    # ===================================================================
    # SUMMARY
    # ===================================================================
    
    print_header "✓ COMPLETE PIPELINE FINISHED"
    
    echo ""
    echo "Generated Files:"
    echo "  • $DATASET"
    echo "  • ebpf_logs/cause_classifier_xgboost.pkl"
    echo "  • ebpf_logs/cause_scaler.pkl"
    echo "  • ebpf_logs/cause_encoder.pkl"
    echo "  • ebpf_logs/cause_metadata.json"
    echo ""
    
    echo "Next Steps:"
    echo "  1. Use the model in production:"
    echo "     from explain_spikes import SpikeCauseExplainer"
    echo "     explainer = SpikeCauseExplainer(...)"
    echo ""
    echo "  2. Review results:"
    echo "     head -20 $DATASET"
    echo "     cat ebpf_logs/cause_metadata.json"
    echo ""
    echo "  3. Read documentation:"
    echo "     cat WORKLOAD_GUIDE.md"
    echo ""
}

# Run
main "$@"
