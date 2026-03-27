#!/bin/bash
#
# TrigGuard Release Script
#
# Builds and publishes the TrigGuard package.
#
# Usage:
#   ./scripts/release.sh           # Full release
#   ./scripts/release.sh --dry-run # Test without publishing
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
DRY_RUN=false
SKIP_TESTS=false

for arg in "$@"; do
    case $arg in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
    esac
done

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║          TRIGGUARD RELEASE                                 ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check we're in the right directory
if [ ! -f "pyproject.toml" ] && [ ! -f "setup.py" ]; then
    echo -e "${RED}Error: Must run from project root${NC}"
    exit 1
fi

# Step 1: Run tests
if [ "$SKIP_TESTS" = false ]; then
    echo -e "${YELLOW}Step 1: Running tests...${NC}"
    echo ""
    
    if command -v pytest &> /dev/null; then
        pytest -v --tb=short
        
        if [ $? -ne 0 ]; then
            echo ""
            echo -e "${RED}Tests failed. Release aborted.${NC}"
            exit 1
        fi
        
        echo ""
        echo -e "${GREEN}Tests passed.${NC}"
    else
        echo -e "${YELLOW}Warning: pytest not found, skipping tests${NC}"
    fi
else
    echo -e "${YELLOW}Step 1: Skipping tests (--skip-tests)${NC}"
fi

echo ""

# Step 2: Clean previous builds
echo -e "${YELLOW}Step 2: Cleaning previous builds...${NC}"
rm -rf dist/ build/ *.egg-info/
echo -e "${GREEN}Clean complete.${NC}"

echo ""

# Step 3: Build package
echo -e "${YELLOW}Step 3: Building package...${NC}"

if command -v python3 &> /dev/null; then
    PYTHON=python3
else
    PYTHON=python
fi

$PYTHON -m pip install --quiet build twine

$PYTHON -m build

if [ $? -ne 0 ]; then
    echo ""
    echo -e "${RED}Build failed. Release aborted.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Build complete.${NC}"
echo ""

# List built artifacts
echo "Built artifacts:"
ls -la dist/

echo ""

# Step 4: Verify package
echo -e "${YELLOW}Step 4: Verifying package...${NC}"
$PYTHON -m twine check dist/*

if [ $? -ne 0 ]; then
    echo ""
    echo -e "${RED}Package verification failed. Release aborted.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Package verified.${NC}"

# Step 5: Publish
if [ "$DRY_RUN" = true ]; then
    echo ""
    echo -e "${YELLOW}Step 5: Dry run - skipping publish${NC}"
    echo ""
    echo "To publish, run:"
    echo "  twine upload dist/*"
    echo ""
    echo "Or for TestPyPI:"
    echo "  twine upload --repository testpypi dist/*"
else
    echo ""
    echo -e "${YELLOW}Step 5: Publishing to PyPI...${NC}"
    echo ""
    
    read -p "Publish to PyPI? (y/N) " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        $PYTHON -m twine upload dist/*
        
        if [ $? -ne 0 ]; then
            echo ""
            echo -e "${RED}Publish failed.${NC}"
            exit 1
        fi
        
        echo ""
        echo -e "${GREEN}Published successfully!${NC}"
    else
        echo "Publish cancelled."
    fi
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║          RELEASE COMPLETE                                   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
