#!/bin/bash

#############################################################################
# PhantomRaven Hunter - Comprehensive NPM Malware Detection
#
# A shell-based scanner for detecting PhantomRaven npm supply chain malware
# and similar attacks using Remote Dynamic Dependencies (RDD).
#
# Usage: ./phantomraven-hunter.sh [OPTIONS] [PATH]
#
# Options:
#   --deep       Enable deep code scanning
#   --paranoid   Enable all checks including timing analysis
#   --verbose    Show detailed output including whitelisted items
#   --help       Show this help message
#
# Exit Codes:
#   0 - Clean (no threats detected)
#   1 - CRITICAL (malware detected - take immediate action)
#   2 - WARNING (suspicious indicators found)
#
# Author: Security Community
# License: MIT
# Version: 1.0.1
#############################################################################

set -e
# Note: pipefail disabled to allow grep failures in pipes without script exit
# set -o pipefail

#############################################################################
# Configuration & Constants
#############################################################################

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly VERSION="1.0.1"

# Data files (external configuration)
readonly DATA_DIR="${SCRIPT_DIR}/data"
readonly MALICIOUS_PACKAGES_FILE="${DATA_DIR}/malicious-packages.txt"
readonly MALICIOUS_DOMAINS_FILE="${DATA_DIR}/malicious-domains.txt"
readonly SAFE_DOMAINS_FILE="${DATA_DIR}/safe-domains.txt"
readonly SAFE_PACKAGES_FILE="${DATA_DIR}/safe-packages.txt"

# Scan configuration
SCAN_PATH="${1:-.}"
DEEP_SCAN=false
PARANOID=false
VERBOSE=false

# Colors for output
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# Findings counters
RDD_COUNT=0
MALICIOUS_PKG_COUNT=0
SUSPICIOUS_SCRIPT_COUNT=0
CREDENTIAL_THEFT_COUNT=0
NETWORK_CALL_COUNT=0
TIMING_SUSPICION_COUNT=0

# Temp files for results
readonly TMP_DIR=$(mktemp -d)
readonly RDD_FINDINGS="${TMP_DIR}/rdd_findings.txt"
readonly MALICIOUS_FINDINGS="${TMP_DIR}/malicious_findings.txt"
readonly SUSPICIOUS_SCRIPTS="${TMP_DIR}/suspicious_scripts.txt"
readonly CREDENTIAL_THEFT="${TMP_DIR}/credential_theft.txt"
readonly NETWORK_CALLS="${TMP_DIR}/network_calls.txt"
readonly TIMING_ISSUES="${TMP_DIR}/timing_issues.txt"

# Cleanup on exit
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}Scan interrupted by user${NC}"; cleanup; exit 130' INT TERM

#############################################################################
# Data Loading Functions
#############################################################################

load_list_from_file() {
    local file="$1"
    local array_name="$2"
    
    if [ ! -f "$file" ]; then
        log_error "Required data file not found: $file"
        exit 1
    fi
    
    # Read file into array, skipping comments and empty lines
    local -a items=()
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        items+=("$line")
    done < "$file"
    
    # Export array globally
    eval "${array_name}=(\"\${items[@]}\")"
}

load_all_data() {
    log_info "Loading malware signatures..."
    
    load_list_from_file "$MALICIOUS_PACKAGES_FILE" "MALICIOUS_PACKAGES"
    load_list_from_file "$MALICIOUS_DOMAINS_FILE" "MALICIOUS_DOMAINS"
    load_list_from_file "$SAFE_DOMAINS_FILE" "SAFE_DOMAINS"
    load_list_from_file "$SAFE_PACKAGES_FILE" "SAFE_PACKAGES"
    
    log_info "Loaded ${#MALICIOUS_PACKAGES[@]} malicious packages"
    log_info "Loaded ${#MALICIOUS_DOMAINS[@]} malicious domains"
    log_info "Loaded ${#SAFE_DOMAINS[@]} safe domains"
    log_info "Loaded ${#SAFE_PACKAGES[@]} safe packages"
}

#############################################################################
# Helper Functions
#############################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_critical() {
    echo -e "${RED}${BOLD}[🚨 CRITICAL]${NC} $1"
}

print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║         PhantomRaven Hunter v1.0.1                        ║
║         Comprehensive NPM Malware Detection               ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

show_help() {
    cat << EOF
PhantomRaven Hunter v${VERSION}
Detect PhantomRaven npm malware and similar supply chain attacks

USAGE:
    $0 [OPTIONS] [PATH]

OPTIONS:
    --deep       Enable deep code scanning (slower, more thorough)
    --paranoid   Enable all checks including timing analysis
    --verbose    Show detailed output including whitelisted items
    --help       Show this help message

EXAMPLES:
    $0 ~/projects                    # Basic scan
    $0 --deep ~/projects             # Deep scan (recommended)
    $0 --paranoid ~/projects         # Maximum security checks

EXIT CODES:
    0 - Clean (no threats detected)
    1 - CRITICAL (malware detected - take immediate action)
    2 - WARNING (suspicious indicators found)

For more information, see the README.md file.
EOF
}

is_safe_domain() {
    local url="$1"
    for domain in "${SAFE_DOMAINS[@]}"; do
        # grep returns 0 on match, 1 on no match - handle both cases explicitly
        if echo "$url" | grep -q "$domain" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

is_safe_package() {
    local package="$1"
    for safe_pkg in "${SAFE_PACKAGES[@]}"; do
        if [ "$package" = "$safe_pkg" ]; then
            return 0
        fi
    done
    return 1
}

#############################################################################
# Detection Functions
#############################################################################

# 1. Detect Remote Dynamic Dependencies
detect_rdd() {
    log_info "Scanning for Remote Dynamic Dependencies (RDD)..."
    
    # Use process substitution to avoid subshell variable scope issues
    while read -r pkg_file; do
        # Check for http:// or https:// in dependencies
        if grep -E '"(dependencies|devDependencies|peerDependencies|optionalDependencies)"' "$pkg_file" -A 200 2>/dev/null | \
           grep -E ':\s*"https?://' > /dev/null 2>&1; then
            
            # Extract the RDD entries using jq  
            while IFS='|' read -r pkg_name pkg_url; do
                
                # Check if it's a safe domain
                if is_safe_domain "$pkg_url"; then
                    [ "$VERBOSE" = true ] && log_info "Safe RDD found: $pkg_name -> $pkg_url (whitelisted domain)"
                else
                    # Check if it's a known malicious domain
                    is_malicious=false
                    for domain in "${MALICIOUS_DOMAINS[@]}"; do
                        if echo "$pkg_url" | grep -q "$domain" 2>/dev/null; then
                            is_malicious=true
                            break
                        fi
                    done
                    
                    if [ "$is_malicious" = true ]; then
                        log_critical "MALICIOUS RDD DETECTED!"
                        echo "CRITICAL|$pkg_file|$pkg_name|$pkg_url|KNOWN_MALICIOUS_DOMAIN" >> "$RDD_FINDINGS"
                    else
                        log_warning "Suspicious RDD found: $pkg_name -> $pkg_url"
                        echo "WARNING|$pkg_file|$pkg_name|$pkg_url|UNKNOWN_DOMAIN" >> "$RDD_FINDINGS"
                    fi
                    ((RDD_COUNT++)) || true
                fi
            done < <(jq -r '
                (.dependencies // {}) + 
                (.devDependencies // {}) + 
                (.peerDependencies // {}) + 
                (.optionalDependencies // {}) | 
                to_entries[] | 
                select(.value | startswith("http://") or startswith("https://")) | 
                "\(.key)|\(.value)"
            ' "$pkg_file" 2>/dev/null)
        fi
    done < <(find "$SCAN_PATH" -name "package.json" -type f 2>/dev/null)
    
    if [ "$RDD_COUNT" -eq 0 ]; then
        log_success "No suspicious RDD found"
    else
        log_warning "Found $RDD_COUNT Remote Dynamic Dependencies"
    fi
}

# 2. Check for known malicious packages
detect_malicious_packages() {
    log_info "Scanning for known malicious packages..."
    
    while read -r pkg_file; do
        for malicious_pkg in "${MALICIOUS_PACKAGES[@]}"; do
            if jq -e --arg pkg "$malicious_pkg" '
                (.dependencies // {}) + 
                (.devDependencies // {}) + 
                (.peerDependencies // {}) + 
                (.optionalDependencies // {}) | 
                has($pkg)
            ' "$pkg_file" > /dev/null 2>&1; then
                
                version=$(jq -r --arg pkg "$malicious_pkg" '
                    ((.dependencies // {}) + 
                    (.devDependencies // {}) + 
                    (.peerDependencies // {}) + 
                    (.optionalDependencies // {}))[$pkg]
                ' "$pkg_file" 2>/dev/null)
                
                log_critical "KNOWN MALICIOUS PACKAGE: $malicious_pkg@$version"
                echo "CRITICAL|$pkg_file|$malicious_pkg|$version" >> "$MALICIOUS_FINDINGS"
                ((MALICIOUS_PKG_COUNT++)) || true
            fi
        done
    done < <(find "$SCAN_PATH" -name "package.json" -type f 2>/dev/null)
    
    if [ "$MALICIOUS_PKG_COUNT" -eq 0 ]; then
        log_success "No known malicious packages found"
    else
        log_critical "Found $MALICIOUS_PKG_COUNT known malicious packages!"
    fi
}

# 3. Analyze lifecycle scripts
analyze_lifecycle_scripts() {
    log_info "Analyzing lifecycle scripts..."
    
    while read -r pkg_file; do
        # Check for suspicious preinstall/postinstall scripts
        while IFS='|' read -r script_name script_content; do
            
            # Flag scripts with network activity
            if echo "$script_content" | grep -iE '(curl|wget|http|fetch|net\.|request)' > /dev/null 2>&1; then
                # Get package name
                pkg_name=$(jq -r '.name // "unknown"' "$pkg_file" 2>/dev/null)
                
                # Check if it's a known safe package
                if is_safe_package "$pkg_name"; then
                    [ "$VERBOSE" = true ] && log_info "Safe install script in $pkg_name (whitelisted)"
                else
                    log_warning "Suspicious lifecycle script in $pkg_name"
                    echo "WARNING|$pkg_file|$pkg_name|$script_name|$script_content" >> "$SUSPICIOUS_SCRIPTS"
                    ((SUSPICIOUS_SCRIPT_COUNT++)) || true
                fi
            fi
            
            # Flag scripts with dangerous commands
            if echo "$script_content" | grep -iE '(eval|exec|child_process|spawn|system)' > /dev/null 2>&1; then
                pkg_name=$(jq -r '.name // "unknown"' "$pkg_file" 2>/dev/null)
                
                if ! is_safe_package "$pkg_name"; then
                    log_warning "Potentially dangerous script in $pkg_name: $script_content"
                    echo "WARNING|$pkg_file|$pkg_name|$script_name|$script_content|DANGEROUS_COMMAND" >> "$SUSPICIOUS_SCRIPTS"
                    ((SUSPICIOUS_SCRIPT_COUNT++)) || true
                fi
            fi
        done < <(jq -r '.scripts // {} | to_entries[] | select(.key | test("(pre|post)?install")) | "\(.key)|\(.value)"' "$pkg_file" 2>/dev/null)
    done < <(find "$SCAN_PATH" -name "package.json" -type f 2>/dev/null)
    
    if [ "$SUSPICIOUS_SCRIPT_COUNT" -eq 0 ]; then
        log_success "No suspicious lifecycle scripts found"
    fi
}

# 4. Deep scan for credential theft patterns
deep_scan_credential_theft() {
    if [ "$DEEP_SCAN" = false ]; then
        return
    fi
    
    log_info "Deep scanning for credential theft patterns..."
    
    # Patterns that indicate credential theft
    local patterns=(
        "NPM_TOKEN"
        "GITHUB_TOKEN"
        "GH_TOKEN"
        "GITLAB_TOKEN"
        "CI_TOKEN"
        "process\.env\."
    )
    
    # Only search in node_modules for performance
    if [ -d "$SCAN_PATH/node_modules" ]; then
        for pattern in "${patterns[@]}"; do
            while read -r js_file; do
                if grep -l "$pattern" "$js_file" 2>/dev/null | head -1; then
                    pkg_name=$(echo "$js_file" | sed -E 's|.*/node_modules/([^/]+)/.*|\1|')
                    log_warning "Credential theft pattern in $pkg_name: $pattern"
                    echo "WARNING|$js_file|$pkg_name|$pattern" >> "$CREDENTIAL_THEFT"
                    ((CREDENTIAL_THEFT_COUNT++)) || true
                    break
                fi
            done < <(find "$SCAN_PATH/node_modules" -type f \( -name "*.js" -o -name "*.mjs" \) 2>/dev/null | head -1000)
        done
    fi
    
    if [ "$CREDENTIAL_THEFT_COUNT" -eq 0 ]; then
        log_success "No credential theft patterns detected"
    fi
}

# 5. Scan for network calls in suspicious packages
scan_network_activity() {
    if [ "$DEEP_SCAN" = false ]; then
        return
    fi
    
    log_info "Scanning for suspicious network activity..."
    
    # Look for fetch, http requests, curl, wget in node_modules
    if [ -d "$SCAN_PATH/node_modules" ]; then
        while read -r js_file; do
            # Check for external network calls (non-npm, non-github)
            while read -r match; do
                pkg_name=$(echo "$js_file" | sed -E 's|.*/node_modules/([^/]+)/.*|\1|')
                line_num=$(echo "$match" | cut -d: -f1)
                
                log_warning "Suspicious network call in $pkg_name"
                echo "WARNING|$js_file|$pkg_name|$line_num|$match" >> "$NETWORK_CALLS"
                ((NETWORK_CALL_COUNT++)) || true
            done < <(grep -nE '(fetch|https?\.get|https?\.request|http\.get|http\.request)\(["\x27]https?://[^"]+' "$js_file" 2>/dev/null | grep -v -E '(npmjs\.org|registry\.npm|github\.com|githubusercontent\.com)' | head -3)
        done < <(find "$SCAN_PATH/node_modules" -type f \( -name "*.js" -o -name "*.mjs" \) 2>/dev/null | head -500)
    fi
    
    if [ "$NETWORK_CALL_COUNT" -eq 0 ]; then
        log_success "No suspicious network activity detected"
    fi
}

# 6. Check installation timing (PhantomRaven was active Aug-Oct 2025)
check_installation_timing() {
    if [ "$PARANOID" = false ]; then
        return
    fi
    
    log_info "Checking installation timing (PhantomRaven active period: Aug-Oct 2025)..."
    
    # Check modification times of node_modules directories
    while read -r nm_dir; do
        # Get modification time
        mod_time=$(stat -c %Y "$nm_dir" 2>/dev/null || stat -f %m "$nm_dir" 2>/dev/null)
        
        # PhantomRaven period: Aug 1 2025 to Oct 31 2025
        aug_2025=$(date -d "2025-08-01" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "2025-08-01" +%s 2>/dev/null)
        oct_2025=$(date -d "2025-10-31" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "2025-10-31" +%s 2>/dev/null)
        
        if [ "$mod_time" -ge "$aug_2025" ] && [ "$mod_time" -le "$oct_2025" ]; then
            mod_date=$(date -d "@$mod_time" 2>/dev/null || date -r "$mod_time" 2>/dev/null)
            log_warning "Packages installed during PhantomRaven active period: $nm_dir"
            echo "WARNING|$nm_dir|$mod_date|PHANTOMRAVEN_PERIOD" >> "$TIMING_ISSUES"
            ((TIMING_SUSPICION_COUNT++)) || true
        fi
    done < <(find "$SCAN_PATH" -type d -name "node_modules" 2>/dev/null)
}

# 7. Check for the specific malicious domain in relevant files ONLY
# FIXED: This function was causing hangs by using grep -r on large directories
scan_for_malicious_domains() {
    log_info "Scanning for known malicious domains in code files..."
    
    # Only scan specific file types in relevant directories, limiting scope
    local file_count=0
    local max_files=1000
    
    for domain in "${MALICIOUS_DOMAINS[@]}"; do
        # Scan package.json files first (most likely to contain malicious RDDs)
        while read -r file; do
            if grep -q "$domain" "$file" 2>/dev/null; then
                log_critical "MALICIOUS DOMAIN FOUND in: $file"
                ((MALICIOUS_PKG_COUNT++)) || true
            fi
        done < <(find "$SCAN_PATH" -name "package.json" -type f 2>/dev/null)
        
        # Then scan JS files in node_modules (limited)
        if [ -d "$SCAN_PATH/node_modules" ]; then
            while read -r file; do
                if grep -q "$domain" "$file" 2>/dev/null; then
                    log_critical "MALICIOUS DOMAIN FOUND in: $file"
                    ((MALICIOUS_PKG_COUNT++)) || true
                    break  # Stop after first match per domain
                fi
            done < <(find "$SCAN_PATH/node_modules" -type f \( -name "*.js" -o -name "*.mjs" \) 2>/dev/null | head -n $max_files)
        fi
        
        # Scan any .js/.ts files in project root (but not deep)
        while read -r file; do
            if grep -q "$domain" "$file" 2>/dev/null; then
                log_critical "MALICIOUS DOMAIN FOUND in: $file"
                ((MALICIOUS_PKG_COUNT++)) || true
            fi
        done < <(find "$SCAN_PATH" -maxdepth 3 -type f \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" \) 2>/dev/null)
    done
}

# 8. Check system compromise
check_system_compromise() {
    if [ "$PARANOID" = false ]; then
        return
    fi
    
    echo ""
    log_info "═══════════════════════════════════════════════════"
    log_info "Running System Compromise Checks..."
    log_info "═══════════════════════════════════════════════════"
    
    # Check .gitconfig
    if [ -f "$HOME/.gitconfig" ]; then
        mod_time=$(stat -c %y "$HOME/.gitconfig" 2>/dev/null || stat -f "%Sm" "$HOME/.gitconfig" 2>/dev/null)
        log_info "~/.gitconfig last modified: $mod_time"
        
        # Check if modified during PhantomRaven period
        file_mod_epoch=$(stat -c %Y "$HOME/.gitconfig" 2>/dev/null || stat -f %m "$HOME/.gitconfig" 2>/dev/null)
        aug_2025=$(date -d "2025-08-01" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "2025-08-01" +%s 2>/dev/null)
        oct_2025=$(date -d "2025-10-31" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "2025-10-31" +%s 2>/dev/null)
        
        if [ "$file_mod_epoch" -ge "$aug_2025" ] && [ "$file_mod_epoch" -le "$oct_2025" ]; then
            log_warning "⚠ .gitconfig was modified during PhantomRaven active period!"
        fi
    fi
    
    # Check .npmrc
    if [ -f "$HOME/.npmrc" ]; then
        mod_time=$(stat -c %y "$HOME/.npmrc" 2>/dev/null || stat -f "%Sm" "$HOME/.npmrc" 2>/dev/null)
        log_info "~/.npmrc last modified: $mod_time"
        
        if grep -q "authToken" "$HOME/.npmrc" 2>/dev/null; then
            log_warning "⚠ .npmrc contains authentication tokens"
        fi
    fi
    
    # Check environment variables
    log_info "Checking environment for exposed credentials..."
    if env | grep -iE '(NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|CI_TOKEN)' > /dev/null 2>&1; then
        log_warning "⚠ Sensitive tokens found in environment variables"
    fi
}

#############################################################################
# Reporting
#############################################################################

generate_report() {
    echo ""
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}                    SCAN RESULTS                           ${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Summary
    echo -e "${BOLD}Summary:${NC}"
    echo "├─ Remote Dynamic Dependencies: $RDD_COUNT"
    echo "├─ Known Malicious Packages: $MALICIOUS_PKG_COUNT"
    echo "├─ Suspicious Lifecycle Scripts: $SUSPICIOUS_SCRIPT_COUNT"
    
    if [ "$DEEP_SCAN" = true ]; then
        echo "├─ Credential Theft Patterns: $CREDENTIAL_THEFT_COUNT"
        echo "├─ Suspicious Network Calls: $NETWORK_CALL_COUNT"
    fi
    
    if [ "$PARANOID" = true ]; then
        echo "└─ Timing Suspicions: $TIMING_SUSPICION_COUNT"
    fi
    
    echo ""
    
    # Detailed findings
    if [ -s "$RDD_FINDINGS" ]; then
        echo -e "${RED}${BOLD}🚨 Remote Dynamic Dependencies:${NC}"
        echo "════════════════════════════════════════"
        while IFS='|' read -r severity file pkg url status; do
            if [ "$severity" = "CRITICAL" ]; then
                echo -e "${RED}[CRITICAL]${NC} $pkg -> $url"
            else
                echo -e "${YELLOW}[WARNING]${NC} $pkg -> $url"
            fi
            echo "  File: $file"
            echo "  Status: $status"
            echo ""
        done < "$RDD_FINDINGS"
    fi
    
    if [ -s "$MALICIOUS_FINDINGS" ]; then
        echo -e "${RED}${BOLD}🚨 Known Malicious Packages:${NC}"
        echo "════════════════════════════════════════"
        while IFS='|' read -r severity file pkg version; do
            echo -e "${RED}[CRITICAL]${NC} $pkg@$version"
            echo "  File: $file"
            echo ""
        done < "$MALICIOUS_FINDINGS"
    fi
    
    if [ -s "$SUSPICIOUS_SCRIPTS" ]; then
        echo -e "${YELLOW}⚠ Suspicious Lifecycle Scripts:${NC}"
        echo "════════════════════════════════════════"
        head -20 "$SUSPICIOUS_SCRIPTS" | while IFS='|' read -r severity file pkg script content extra; do
            echo -e "${YELLOW}[WARNING]${NC} $pkg - $script"
            echo "  File: $file"
            echo "  Content: $content"
            [ -n "$extra" ] && echo "  Note: $extra"
            echo ""
        done
        
        line_count=$(wc -l < "$SUSPICIOUS_SCRIPTS")
        if [ "$line_count" -gt 20 ]; then
            echo "... and $((line_count - 20)) more"
            echo ""
        fi
    fi
    
    # Final verdict
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    if [ "$MALICIOUS_PKG_COUNT" -gt 0 ] || \
       ([ "$RDD_COUNT" -gt 0 ] && grep -q "CRITICAL" "$RDD_FINDINGS" 2>/dev/null); then
        echo -e "${RED}${BOLD}🚨 CRITICAL: MALWARE DETECTED!${NC}"
        echo ""
        echo "IMMEDIATE ACTIONS REQUIRED:"
        echo "1. DO NOT run npm install"
        echo "2. Disconnect this machine from network"
        echo "3. Rotate ALL credentials immediately:"
        echo "   - GitHub tokens: https://github.com/settings/tokens"
        echo "   - npm tokens: npm token list && npm token revoke <id>"
        echo "   - CI/CD secrets (GitHub Actions, GitLab, Jenkins, CircleCI)"
        echo "4. Check ~/.gitconfig and ~/.npmrc for exposure"
        echo "5. Review git audit logs for unauthorized activity"
        echo "6. Scan system for other malware"
        echo "7. Consider this machine compromised"
        
        exit 1
    elif [ "$RDD_COUNT" -gt 0 ] || [ "$SUSPICIOUS_SCRIPT_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}${BOLD}⚠ WARNING: Suspicious indicators found${NC}"
        echo ""
        echo "RECOMMENDED ACTIONS:"
        echo "1. Review the findings above carefully"
        echo "2. Verify all flagged packages are legitimate"
        echo "3. Consider rotating credentials as a precaution"
        echo "4. Run with --paranoid flag for deeper analysis"
        
        exit 2
    else
        echo -e "${GREEN}${BOLD}✓ No critical threats detected${NC}"
        echo ""
        echo "Your npm projects appear clean based on known PhantomRaven indicators."
        echo ""
        if [ "$DEEP_SCAN" = false ]; then
            echo "💡 Tip: Run with --deep or --paranoid for more thorough scanning"
        fi
        
        exit 0
    fi
}

#############################################################################
# Argument Parsing
#############################################################################

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --deep)
                DEEP_SCAN=true
                shift
                ;;
            --paranoid)
                PARANOID=true
                DEEP_SCAN=true
                shift
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                SCAN_PATH="$1"
                shift
                ;;
        esac
    done
}

#############################################################################
# Main Execution
#############################################################################

main() {
    parse_arguments "$@"
    
    print_banner
    
    echo -e "${BOLD}Configuration:${NC}"
    echo "  Scan Path: $SCAN_PATH"
    echo "  Deep Scan: $DEEP_SCAN"
    echo "  Paranoid Mode: $PARANOID"
    echo "  Verbose: $VERBOSE"
    echo ""
    
    # Check dependencies
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed. Install with: sudo apt install jq"
        exit 1
    fi
    
    if [ ! -d "$SCAN_PATH" ]; then
        log_error "Scan path does not exist: $SCAN_PATH"
        exit 1
    fi
    
    if [ ! -d "$DATA_DIR" ]; then
        log_error "Data directory not found: $DATA_DIR"
        log_error "Make sure malicious-packages.txt and other data files are in $DATA_DIR/"
        exit 1
    fi
    
    # Load external data files
    load_all_data
    
    # Run detection functions
    detect_rdd
    detect_malicious_packages
    analyze_lifecycle_scripts
    scan_for_malicious_domains
    
    if [ "$DEEP_SCAN" = true ]; then
        deep_scan_credential_theft
        scan_network_activity
    fi
    
    if [ "$PARANOID" = true ]; then
        check_installation_timing
        check_system_compromise
    fi
    
    # Generate report
    generate_report
}

# Run main
main "$@"