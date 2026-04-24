#!/bin/bash
# ===================================================================
# QUICK START - Run everything with one command
# ===================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         ANOMALY SCHEDULER LATENCY - ML PIPELINE          ║"
echo "║              Linux Automated Data Generation             ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check prerequisites
echo ""
echo "Checking prerequisites..."

# Check compiler
if ! command -v gcc &> /dev/null; then
    echo -e "${RED}ERROR: gcc not found. Install with:${NC}"
    echo "  sudo apt-get install build-essential"
    exit 1
fi
echo -e "${GREEN}✓ GCC${NC}"

# Check Python3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: Python3 not found. Install with:${NC}"
    echo "  sudo apt-get install python3 python3-pip"
    exit 1
fi
echo -e "${GREEN}✓ Python3${NC}"

# Check Python packages
if ! python3 -c "import numpy, pandas, sklearn, xgboost" 2>/dev/null; then
    echo -e "${RED}WARNING: Missing Python packages${NC}"
    echo "Installing: pip3 install numpy pandas scikit-learn xgboost"
    pip3 install --user numpy pandas scikit-learn xgboost
fi
echo -e "${GREEN}✓ Python packages${NC}"

# Check eBPF collector
COLLECTOR="ebpf_logs/collector"
if [ ! -f "$COLLECTOR" ]; then
    echo -e "${RED}WARNING: eBPF collector not found${NC}"
    echo "Try compiling it:"
    echo "  cd ebpf_logs && gcc -pthread collector.c -o collector && cd .."
    echo ""
    echo "Continuing with synthetic data mode..."
fi

# Make scripts executable
chmod +x run_*.sh 2>/dev/null || true

echo -e "${GREEN}✓ All checks passed${NC}"
echo ""

# Ask what to run
echo "What would you like to do?"
echo ""
echo "  1) Run COMPLETE pipeline (dataset + training + inference)"
echo "  2) Generate DATASET ONLY (faster, no training)"
echo "  3) View DOCUMENTATION"
echo "  4) ADVANCED options"
echo ""
read -p "Choose (1-4): " choice

case $choice in
    1)
        echo ""
        echo -e "${BLUE}Running complete pipeline...${NC}"
        echo "This will take 5-15 minutes depending on your system"
        echo ""
        bash run_complete_pipeline.sh
        ;;
    2)
        echo ""
        echo -e "${BLUE}Generating dataset...${NC}"
        echo "This will take 2-8 minutes"
        echo ""
        bash run_dataset_generation.sh
        echo ""
        echo -e "${GREEN}✓ Dataset ready at: ebpf_logs/labeled_dataset.csv${NC}"
        ;;
    3)
        echo ""
        echo -e "${BLUE}Opening documentation...${NC}"
        echo ""
        # Try different pagers
        if command -v less &> /dev/null; then
            less LINUX_SETUP_GUIDE.md
        elif command -v more &> /dev/null; then
            more LINUX_SETUP_GUIDE.md
        else
            cat LINUX_SETUP_GUIDE.md
        fi
        ;;
    4)
        echo ""
        echo "Advanced Options:"
        echo ""
        echo "  A) Compile workloads only"
        echo "  B) Run single workload manually"
        echo "  C) Train model only (on existing dataset)"
        echo "  D) Test inference only"
        echo "  E) View current dataset statistics"
        echo "  F) Run with collector debugging"
        echo ""
        read -p "Choose (A-F): " adv_choice
        
        case $adv_choice in
            A)
                echo "Compiling workloads..."
                cd workload && bash compile_all.sh && cd ..
                echo -e "${GREEN}✓ Done${NC}"
                ;;
            B)
                echo "Available workloads:"
                ls -1 workload/*.c 2>/dev/null | xargs -n1 basename | sed 's/.c//'
                echo ""
                read -p "Enter workload name (e.g., 1_baseline): " workload_name
                if [ -f "workload/$workload_name" ]; then
                    echo "Running $workload_name..."
                    "workload/$workload_name"
                else
                    echo "Workload not found. Compile first: cd workload && bash compile_all.sh"
                fi
                ;;
            C)
                echo "Training model on existing dataset..."
                if [ ! -f "ebpf_logs/labeled_dataset.csv" ]; then
                    echo "No dataset found. Generate first with option 2"
                    exit 1
                fi
                python3 train_cause_classifier.py
                ;;
            D)
                echo "Testing inference..."
                if [ ! -f "ebpf_logs/cause_classifier_xgboost.pkl" ]; then
                    echo "No model found. Train first with option C"
                    exit 1
                fi
                python3 explain_spikes.py
                ;;
            E)
                if [ -f "ebpf_logs/labeled_dataset_summary.txt" ]; then
                    cat ebpf_logs/labeled_dataset_summary.txt
                else
                    echo "No summary found. Generate dataset first"
                fi
                ;;
            F)
                echo "Running with collector debugging..."
                echo "Make sure collector exists at: ebpf_logs/collector"
                echo ""
                cd ebpf_logs
                echo "Testing collector..."
                if [ -f "collector" ]; then
                    timeout 10 ./collector debug 5 1 100 || true
                    echo ""
                    echo "Check output above for any errors"
                else
                    echo "Collector not found!"
                fi
                ;;
            *)
                echo "Invalid option"
                ;;
        esac
        ;;
    *)
        echo "Invalid option"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    PROCESS COMPLETE!                      ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Next steps:"
echo "  1. Check results: cat ebpf_logs/labeled_dataset.csv"
echo "  2. Train model: python3 train_cause_classifier.py"
echo "  3. Test predictions: python3 explain_spikes.py"
echo ""
echo "Documentation: cat LINUX_SETUP_GUIDE.md"
echo ""
