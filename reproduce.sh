#!/usr/bin/env bash
# ============================================================================
# BinMind GAPSBV — One-Click Reproduction Script
# ============================================================================
# Usage: bash reproduce.sh
#
# Reproduces all results from the paper:
#   BinMind: Multi-Vector False Positive Reduction for
#   Binary-Level Vulnerability Detection
#
# Requirements: Python 3.10+, pip, gcc, binutils (objdump, nm)
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "============================================================"
echo "  BinMind GAPSBV — Reproduction Script"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"
echo ""

# ---- Step 0: Check dependencies ----
echo -e "${YELLOW}[0/7] Checking dependencies...${NC}"
MISSING=""
for cmd in python3 gcc objdump nm; do
    if ! command -v "$cmd" &>/dev/null; then
        MISSING="$MISSING $cmd"
    fi
done
if [ -n "$MISSING" ]; then
    echo -e "${RED}Missing dependencies:$MISSING${NC}"
    echo "Install: apt-get install python3 gcc binutils"
    exit 1
fi
echo -e "${GREEN}  All dependencies found.${NC}"

# ---- Step 1: Install Python packages ----
echo -e "${YELLOW}[1/7] Installing Python packages...${NC}"
pip install -q matplotlib numpy networkx pyelftools capstone 2>/dev/null || \
    pip install --user -q matplotlib numpy networkx pyelftools capstone 2>/dev/null || true
echo -e "${GREEN}  Done.${NC}"

# ---- Step 2: Compile benchmark samples ----
echo -e "${YELLOW}[2/7] Compiling benchmark samples...${NC}"
COMPILED=0
FAILED=0
for sample_dir in tests/samples/*/; do
    if [ -f "${sample_dir}Makefile" ] || [ -f "${sample_dir}makefile" ]; then
        (cd "$sample_dir" && make clean 2>/dev/null; make 2>/dev/null) && COMPILED=$((COMPILED+1)) || FAILED=$((FAILED+1))
    fi
done
echo -e "${GREEN}  Compiled: $COMPILED, Failed: $FAILED${NC}"

# ---- Step 3: Run regression tests ----
echo -e "${YELLOW}[3/7] Running unified regression tests...${NC}"
python3 tests/regression/run/unified_regression_runner.py 2>&1 | tail -5
echo -e "${GREEN}  Done.${NC}"

# ---- Step 4: Run cross-type benchmark ----
echo -e "${YELLOW}[4/7] Running cross-type benchmark...${NC}"
python3 eval/cross_type_benchmark.py 2>&1 | tail -10
echo -e "${GREEN}  Done.${NC}"

# ---- Step 5: Run multi-tool comparison ----
echo -e "${YELLOW}[5/7] Running multi-tool comparison...${NC}"
python3 eval/multi_tool_comparison.py 2>&1 | tail -10
echo -e "${GREEN}  Done.${NC}"

# ---- Step 6: Run ablation study ----
echo -e "${YELLOW}[6/7] Running ablation study...${NC}"
python3 eval/gapsbv_ablation.py 2>&1 | tail -10
echo -e "${GREEN}  Done.${NC}"

# ---- Step 7: Generate paper figures & final verification ----
echo -e "${YELLOW}[7/7] Generating paper figures & final verification...${NC}"
python3 eval/generate_paper_figures.py 2>&1 | tail -5
echo ""
echo "============================================================"
python3 eval/verify_all.py 2>&1
echo "============================================================"

echo ""
echo -e "${GREEN}Reproduction complete.${NC}"
echo "Key outputs:"
echo "  eval/benchmark_comparison.png     — F1 comparison chart"
echo "  eval/cross_type_comparison.png    — Cross-type comparison"
echo "  eval/multi_vuln_comparison.png    — Multi-vuln comparison"
echo "  eval/f1_fpr_comparison.png        — F1 vs FPR chart"
echo "  eval/benchmark_final.csv          — Per-sample results"
echo "  eval/benchmark_final_report.json  — Full metrics JSON"
echo "  eval/generate_paper_figures.py     — LaTeX tables (run manually for output)"
