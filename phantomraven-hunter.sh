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
#   --deep         Enable deep code scanning
#   --paranoid     Enable all checks including timing analysis
#   --verbose      Show detailed output including whitelisted items
#   --json         Output results in JSON format
#   --dry-run      Show what would be scanned without executing
#   --no-cache     Disable signature caching
#   --parallel     Use parallel processing (requires GNU parallel)
#   --help         Show this help message
#   --version      Show version information
#
# Exit Codes:
#   0 - Clean (no threats detected)
#   1 - CRITICAL (malware detected - take immediate action)
#   2 - WARNING (suspicious indicators found)
#
# Author: Security Community
# License: MIT
# Version: 1.0.2
#############################################################################

set -e
# Note: pipefail disabled to allow grep failures in pipes without script exit
# set -o pipefail

#############################################################################
# Configuration & Constants
#############################################################################

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly VERSION="1.0.2"

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
JSON_OUTPUT=false
DRY_RUN=false
USE_CACHE=true
USE_PARALLEL=false

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

# Performance tracking
SCAN_START_TIME=0
FILES_SCANNED=0
TOTAL_FILES=0

# Temp files for results
readonly TMP_DIR=$(mktemp -d)
readonly RDD_FINDINGS="${TMP_DIR}/rdd_findings.txt"
readonly MALICIOUS_FINDINGS="${TMP_DIR}/malicious_findings.txt"
readonly SUSPICIOUS_SCRIPTS="${TMP_DIR}/suspicious_scripts.txt"
readonly CREDENTIAL_THEFT="${TMP_DIR}/credential_theft.txt"
readonly NETWORK_CALLS="${TMP_DIR}/network_calls.txt"
readonly TIMING_ISSUES="${TMP_DIR}/timing_issues.txt"
readonly CACHE_DIR="${TMP_DIR}/cache"
readonly ERROR_LOG="${TMP_DIR}/errors.log"

# Cleanup on exit
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}Scan interrupted by user${NC}"; cleanup; exit 130' INT TERM

#############################################################################
# Utility Functions
#############################################################################

# Detect OS for cross-platform compatibility
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    else
        echo "unknown"
    fi
}

readonly OS_TYPE=$(detect_os)

# Cross-platform stat
get_file_mtime() {
    local file="$1"
    if [ "$OS_TYPE" = "macos" ]; then
        stat -f %m "$file" 2>/dev/null || echo ""
    else
        stat -c %Y "$file" 2>/dev/null || echo ""
    fi
}

get_file_mtime_readable() {
    local file="$1"
    if [ "$OS_TYPE" = "macos" ]; then
        stat -f "%Sm" "$file" 2>/dev/null || echo "unknown"
    else
        stat -c %y "$file" 2>/dev/null || echo "unknown"
    fi
}

# Progress bar (Fixed: separate stdout/stderr for JSON mode)
show_progress() {
    if [ "$DRY_RUN" = true ]; then
        return
    fi
    
    local current=$1
    local total=$2
    local task="${3:-Scanning}"
    
    if [ "$total" -eq 0 ]; then
        return
    fi
    
    local percent=$((current * 100 / total))
    local filled=$((percent / 2))
    local empty=$((50 - filled))
    
    # Build progress bar strings safely
    local filled_bar=""
    local empty_bar=""
    
    if [ "$filled" -gt 0 ]; then
        filled_bar=$(printf "%${filled}s" | tr ' ' '#')
    fi
    
    if [ "$empty" -gt 0 ]; then
        empty_bar=$(printf "%${empty}s" | tr ' ' '-')
    fi
    
    # Always output to stderr in JSON mode
    if [ "$JSON_OUTPUT" = true ]; then
        printf "\r[INFO] %s: [%s%s] %3d%% (%d/%d)" "$task" "$filled_bar" "$empty_bar" "$percent" "$current" "$total" >&2
    else
        printf "\r${BLUE}[INFO]${NC} %s: [%s%s] %3d%% (%d/%d)" "$task" "$filled_bar" "$empty_bar" "$percent" "$current" "$total"
    fi
}

clear_progress() {
    if [ "$DRY_RUN" = true ]; then
        return
    fi
    
    if [ "$JSON_OUTPUT" = true ]; then
        printf "\r\033[K" >&2
    else
        printf "\r\033[K"
    fi
}

#############################################################################
# Data Loading Functions
#############################################################################

# Generate hash of data files for caching
get_data_hash() {
    if command -v sha256sum &> /dev/null; then
        cat "$MALICIOUS_PACKAGES_FILE" \
            "$MALICIOUS_DOMAINS_FILE" \
            "$SAFE_DOMAINS_FILE" \
            "$SAFE_PACKAGES_FILE" 2>/dev/null | \
        sha256sum | cut -d' ' -f1
    elif command -v shasum &> /dev/null; then
        cat "$MALICIOUS_PACKAGES_FILE" \
            "$MALICIOUS_DOMAINS_FILE" \
            "$SAFE_DOMAINS_FILE" \
            "$SAFE_PACKAGES_FILE" 2>/dev/null | \
        shasum -a 256 | cut -d' ' -f1
    else
        echo "no-cache"
    fi
}

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

save_cache() {
    mkdir -p "$CACHE_DIR"
    local cache_file="$CACHE_DIR/signatures.cache"
    
    {
        echo "# Cache generated at $(date)"
        echo "CACHE_HASH='$(get_data_hash)'"
        declare -p MALICIOUS_PACKAGES
        declare -p MALICIOUS_DOMAINS
        declare -p SAFE_DOMAINS
        declare -p SAFE_PACKAGES
    } > "$cache_file"
}

load_from_cache() {
    local cache_file="$CACHE_DIR/signatures.cache"
    
    if [ ! -f "$cache_file" ]; then
        return 1
    fi
    
    # shellcheck source=/dev/null
    source "$cache_file" 2>/dev/null || return 1
    
    local current_hash=$(get_data_hash)
    if [ "$CACHE_HASH" != "$current_hash" ]; then
        return 1
    fi
    
    return 0
}

load_all_data() {
    if [ "$USE_CACHE" = true ] && load_from_cache; then
        log_info "Loaded signatures from cache"
    else
        log_info "Loading malware signatures..."
        
        load_list_from_file "$MALICIOUS_PACKAGES_FILE" "MALICIOUS_PACKAGES"
        load_list_from_file "$MALICIOUS_DOMAINS_FILE" "MALICIOUS_DOMAINS"
        load_list_from_file "$SAFE_DOMAINS_FILE" "SAFE_DOMAINS"
        load_list_from_file "$SAFE_PACKAGES_FILE" "SAFE_PACKAGES"
        
        if [ "$USE_CACHE" = true ]; then
            save_cache
        fi
    fi
    
    log_info "Loaded ${#MALICIOUS_PACKAGES[@]} malicious packages"
    log_info "Loaded ${#MALICIOUS_DOMAINS[@]} malicious domains"
    log_info "Loaded ${#SAFE_DOMAINS[@]} safe domains"
    log_info "Loaded ${#SAFE_PACKAGES[@]} safe packages"
}

#############################################################################
# Helper Functions
#############################################################################

log_info() {
    if [ "$JSON_OUTPUT" = true ]; then
        echo -e "${BLUE}[INFO]${NC} $1" >&2
    else
        echo -e "${BLUE}[INFO]${NC} $1"
    fi
}

log_success() {
    if [ "$JSON_OUTPUT" = true ]; then
        echo -e "${GREEN}[✓]${NC} $1" >&2
    else
        echo -e "${GREEN}[✓]${NC} $1"
    fi
}

log_warning() {
    if [ "$JSON_OUTPUT" = true ]; then
        echo -e "${YELLOW}[⚠]${NC} $1" >&2
    else
        echo -e "${YELLOW}[⚠]${NC} $1"
    fi
}

log_error() {
    if [ "$JSON_OUTPUT" = true ]; then
        echo -e "${RED}[✗]${NC} $1" >&2
    else
        echo -e "${RED}[✗]${NC} $1" >&2
    fi
    echo "[ERROR] $1" >> "$ERROR_LOG"
}

log_critical() {
    if [ "$JSON_OUTPUT" = true ]; then
        echo -e "${RED}${BOLD}[🚨 CRITICAL]${NC} $1" >&2
    else
        echo -e "${RED}${BOLD}[🚨 CRITICAL]${NC} $1"
    fi
}

print_banner() {
    local target_stream=1
    if [ "$JSON_OUTPUT" = true ]; then
        target_stream=2
    fi
    
    echo -e "${CYAN}${BOLD}" >&$target_stream
    cat >&$target_stream << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║         PhantomRaven Hunter v1.0.2                        ║
║         Comprehensive NPM Malware Detection               ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}" >&$target_stream
}

show_help() {
    cat << EOF
PhantomRaven Hunter v${VERSION} (Enhanced)
Detect PhantomRaven npm malware and similar supply chain attacks

USAGE:
    $(basename "$0") [OPTIONS] [PATH]

OPTIONS:
    --deep         Enable deep code scanning (slower, more thorough)
    --paranoid     Enable all checks including timing analysis
    --verbose      Show detailed output including whitelisted items
    --json         Output results in JSON format
    --dry-run      Show what would be scanned without executing
    --no-cache     Disable signature caching
    --parallel     Use parallel processing (requires GNU parallel)
    --help         Show this help message
    --version      Show version information

EXAMPLES:
    $(basename "$0") ~/projects                      # Basic scan
    $(basename "$0") --deep ~/projects               # Deep scan (recommended)
    $(basename "$0") --paranoid ~/projects           # Maximum security checks
    $(basename "$0") --json ~/projects > report.json # JSON output

EXIT CODES:
    0 - Clean (no threats detected)
    1 - CRITICAL (malware detected - take immediate action)
    2 - WARNING (suspicious indicators found)

REQUIREMENTS:
    - jq (JSON processor)
    - GNU parallel (optional, for --parallel)

For more information, see the README.md file.
EOF
}

is_safe_domain() {
    local url="$1"
    for pattern in "${SAFE_DOMAINS[@]}"; do
        # Support both exact match and regex patterns
        if [[ "$url" =~ $pattern ]]; then
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

# Safe jq execution with error handling
safe_jq() {
    local filter="$1"
    local file="$2"
    local error_file="${TMP_DIR}/jq_error_$(basename "$file" | tr '/' '_').log"
    
    if ! jq -r "$filter" "$file" 2>"$error_file"; then
        if [ -s "$error_file" ]; then
            log_warning "Failed to parse JSON in $file"
        fi
        return 1
    fi
    return 0
}

#############################################################################
# Validation Functions
#############################################################################

validate_dependencies() {
    local missing_deps=()
    
    if ! command -v jq &> /dev/null; then
        missing_deps+=("jq")
    fi
    
    if [ "$USE_PARALLEL" = true ] && ! command -v parallel &> /dev/null; then
        log_warning "GNU parallel not found, falling back to sequential processing"
        USE_PARALLEL=false
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_error "Install with: sudo apt install ${missing_deps[*]} (Ubuntu/Debian)"
        log_error "           or: brew install ${missing_deps[*]} (macOS)"
        exit 1
    fi
}

validate_scan_path() {
    if [ ! -d "$SCAN_PATH" ]; then
        log_error "Scan path does not exist: $SCAN_PATH"
        exit 1
    fi
    
    # Check if directory is readable
    if [ ! -r "$SCAN_PATH" ]; then
        log_error "Scan path is not readable: $SCAN_PATH"
        exit 1
    fi
    
    # Check for package.json files
    local pkg_count=$(find "$SCAN_PATH" -name "package.json" -type f 2>/dev/null | wc -l | tr -d ' ')
    
    if [ "$pkg_count" -eq 0 ]; then
        log_warning "No package.json files found in $SCAN_PATH"
        
        if [ "$DRY_RUN" = false ] && [ "$JSON_OUTPUT" = false ]; then
            read -p "Continue anyway? (y/N) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 0
            fi
        fi
    else
        log_info "Found $pkg_count package.json file(s)"
    fi
}

validate_data_files() {
    local missing_files=()
    
    if [ ! -f "$MALICIOUS_PACKAGES_FILE" ]; then
        missing_files+=("$MALICIOUS_PACKAGES_FILE")
    fi
    
    if [ ! -f "$MALICIOUS_DOMAINS_FILE" ]; then
        missing_files+=("$MALICIOUS_DOMAINS_FILE")
    fi
    
    if [ ! -f "$SAFE_DOMAINS_FILE" ]; then
        missing_files+=("$SAFE_DOMAINS_FILE")
    fi
    
    if [ ! -f "$SAFE_PACKAGES_FILE" ]; then
        missing_files+=("$SAFE_PACKAGES_FILE")
    fi
    
    if [ ${#missing_files[@]} -gt 0 ]; then
        log_error "Missing required data files:"
        for file in "${missing_files[@]}"; do
            log_error "  - $file"
        done
        exit 1
    fi
}

#############################################################################
# Detection Functions
#############################################################################

# 1. Detect Remote Dynamic Dependencies (Optimized)
detect_rdd() {
    log_info "Scanning for Remote Dynamic Dependencies (RDD)..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would scan package.json files for HTTP(S) dependencies"
        return
    fi
    
    local pkg_files=()
    while IFS= read -r file; do
        pkg_files+=("$file")
    done < <(find "$SCAN_PATH" -name "package.json" -type f 2>/dev/null)
    
    local total=${#pkg_files[@]}
    local current=0
    
    for pkg_file in "${pkg_files[@]}"; do
        ((current++)) || true
        show_progress "$current" "$total" "Scanning RDD"
        
        # Check for http:// or https:// in dependencies
        if ! grep -E '"(dependencies|devDependencies|peerDependencies|optionalDependencies)"' "$pkg_file" -A 200 2>/dev/null | \
           grep -E ':\s*"https?://' > /dev/null 2>&1; then
            continue
        fi
        
        # Extract RDD entries
        while IFS='|' read -r pkg_name pkg_url; do
            [ -z "$pkg_name" ] && continue
            
            if is_safe_domain "$pkg_url"; then
                [ "$VERBOSE" = true ] && log_info "Safe RDD: $pkg_name -> $pkg_url"
            else
                # Check against malicious domains
                local is_malicious=false
                for domain in "${MALICIOUS_DOMAINS[@]}"; do
                    if [[ "$pkg_url" =~ $domain ]]; then
                        is_malicious=true
                        break
                    fi
                done
                
                if [ "$is_malicious" = true ]; then
                    log_critical "MALICIOUS RDD DETECTED!"
                    echo "CRITICAL|$pkg_file|$pkg_name|$pkg_url|KNOWN_MALICIOUS_DOMAIN" >> "$RDD_FINDINGS"
                else
                    log_warning "Suspicious RDD: $pkg_name -> $pkg_url"
                    echo "WARNING|$pkg_file|$pkg_name|$pkg_url|UNKNOWN_DOMAIN" >> "$RDD_FINDINGS"
                fi
                ((RDD_COUNT++)) || true
            fi
        done < <(safe_jq '
            (.dependencies // {}) + 
            (.devDependencies // {}) + 
            (.peerDependencies // {}) + 
            (.optionalDependencies // {}) | 
            to_entries[] | 
            select(.value | startswith("http://") or startswith("https://")) | 
            "\(.key)|\(.value)"
        ' "$pkg_file" 2>/dev/null || true)
        
        ((FILES_SCANNED++)) || true
    done
    
    clear_progress
    
    if [ "$RDD_COUNT" -eq 0 ]; then
        log_success "No suspicious RDD found"
    else
        log_warning "Found $RDD_COUNT Remote Dynamic Dependencies"
    fi
}

# 2. Check for known malicious packages (Optimized)
detect_malicious_packages() {
    log_info "Scanning for known malicious packages..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would check ${#MALICIOUS_PACKAGES[@]} known malicious packages"
        return
    fi
    
    local pkg_files=()
    while IFS= read -r file; do
        pkg_files+=("$file")
    done < <(find "$SCAN_PATH" -name "package.json" -type f 2>/dev/null)
    
    local total=${#pkg_files[@]}
    local current=0
    
    for pkg_file in "${pkg_files[@]}"; do
        ((current++)) || true
        show_progress "$current" "$total" "Checking packages"
        
        for malicious_pkg in "${MALICIOUS_PACKAGES[@]}"; do
            if jq -e --arg pkg "$malicious_pkg" '
                (.dependencies // {}) + 
                (.devDependencies // {}) + 
                (.peerDependencies // {}) + 
                (.optionalDependencies // {}) | 
                has($pkg)
            ' "$pkg_file" > /dev/null 2>&1; then
                
                local version=$(safe_jq --arg pkg "$malicious_pkg" '
                    ((.dependencies // {}) + 
                    (.devDependencies // {}) + 
                    (.peerDependencies // {}) + 
                    (.optionalDependencies // {}))[$pkg]
                ' "$pkg_file" 2>/dev/null || echo "unknown")
                
                log_critical "KNOWN MALICIOUS PACKAGE: $malicious_pkg@$version"
                echo "CRITICAL|$pkg_file|$malicious_pkg|$version" >> "$MALICIOUS_FINDINGS"
                ((MALICIOUS_PKG_COUNT++)) || true
            fi
        done
        
        ((FILES_SCANNED++)) || true
    done
    
    clear_progress
    
    if [ "$MALICIOUS_PKG_COUNT" -eq 0 ]; then
        log_success "No known malicious packages found"
    else
        log_critical "Found $MALICIOUS_PKG_COUNT known malicious packages!"
    fi
}

# 3. Analyze lifecycle scripts
analyze_lifecycle_scripts() {
    log_info "Analyzing lifecycle scripts..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would analyze install/postinstall scripts"
        return
    fi
    
    local pkg_files=()
    while IFS= read -r file; do
        pkg_files+=("$file")
    done < <(find "$SCAN_PATH" -name "package.json" -type f 2>/dev/null)
    
    local total=${#pkg_files[@]}
    local current=0
    
    for pkg_file in "${pkg_files[@]}"; do
        ((current++)) || true
        show_progress "$current" "$total" "Analyzing scripts"
        
        while IFS='|' read -r script_name script_content; do
            [ -z "$script_name" ] && continue
            
            local pkg_name=$(safe_jq '.name // "unknown"' "$pkg_file" 2>/dev/null || echo "unknown")
            
            # Network activity check
            if echo "$script_content" | grep -iE '(curl|wget|http|fetch|net\.|request)' > /dev/null 2>&1; then
                if is_safe_package "$pkg_name"; then
                    [ "$VERBOSE" = true ] && log_info "Safe install script in $pkg_name"
                else
                    log_warning "Suspicious lifecycle script in $pkg_name"
                    echo "WARNING|$pkg_file|$pkg_name|$script_name|$script_content" >> "$SUSPICIOUS_SCRIPTS"
                    ((SUSPICIOUS_SCRIPT_COUNT++)) || true
                fi
            fi
            
            # Dangerous commands check
            if echo "$script_content" | grep -iE '(eval|exec|child_process|spawn|system)' > /dev/null 2>&1; then
                if ! is_safe_package "$pkg_name"; then
                    log_warning "Dangerous script in $pkg_name: $script_content"
                    echo "WARNING|$pkg_file|$pkg_name|$script_name|$script_content|DANGEROUS_COMMAND" >> "$SUSPICIOUS_SCRIPTS"
                    ((SUSPICIOUS_SCRIPT_COUNT++)) || true
                fi
            fi
        done < <(safe_jq '.scripts // {} | to_entries[] | select(.key | test("(pre|post)?install")) | "\(.key)|\(.value)"' "$pkg_file" 2>/dev/null || true)
        
        ((FILES_SCANNED++)) || true
    done
    
    clear_progress
    
    if [ "$SUSPICIOUS_SCRIPT_COUNT" -eq 0 ]; then
        log_success "No suspicious lifecycle scripts found"
    fi
}

# 4. Deep scan for credential theft patterns (Optimized)
deep_scan_credential_theft() {
    if [ "$DEEP_SCAN" = false ]; then
        return
    fi
    
    log_info "Deep scanning for credential theft patterns..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would scan for credential theft in node_modules"
        return
    fi
    
    if [ ! -d "$SCAN_PATH/node_modules" ]; then
        log_info "No node_modules directory found, skipping credential theft scan"
        return
    fi
    
    # Build combined grep pattern
    local pattern_string="NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|CI_TOKEN|process\.env\."
    
    # Use parallel if available
    if [ "$USE_PARALLEL" = true ]; then
        find "$SCAN_PATH/node_modules" -type f \( -name "*.js" -o -name "*.mjs" \) 2>/dev/null | \
        head -1000 | \
        parallel -j4 "grep -l -E '$pattern_string' {} 2>/dev/null || true" | \
        while read -r js_file; do
            local pkg_name=$(echo "$js_file" | sed -E 's|.*/node_modules/([^/]+)/.*|\1|')
            log_warning "Credential theft pattern in $pkg_name"
            echo "WARNING|$js_file|$pkg_name|MULTIPLE_PATTERNS" >> "$CREDENTIAL_THEFT"
            ((CREDENTIAL_THEFT_COUNT++)) || true
        done
    else
        while read -r js_file; do
            if grep -l -E "$pattern_string" "$js_file" 2>/dev/null > /dev/null; then
                local pkg_name=$(echo "$js_file" | sed -E 's|.*/node_modules/([^/]+)/.*|\1|')
                log_warning "Credential theft pattern in $pkg_name"
                echo "WARNING|$js_file|$pkg_name|MULTIPLE_PATTERNS" >> "$CREDENTIAL_THEFT"
                ((CREDENTIAL_THEFT_COUNT++)) || true
            fi
        done < <(find "$SCAN_PATH/node_modules" -type f \( -name "*.js" -o -name "*.mjs" \) 2>/dev/null | head -1000)
    fi
    
    if [ "$CREDENTIAL_THEFT_COUNT" -eq 0 ]; then
        log_success "No credential theft patterns detected"
    fi
}

# 5. Scan for network activity (Optimized)
scan_network_activity() {
    if [ "$DEEP_SCAN" = false ]; then
        return
    fi
    
    log_info "Scanning for suspicious network activity..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would scan for network calls in node_modules"
        return
    fi
    
    if [ ! -d "$SCAN_PATH/node_modules" ]; then
        return
    fi
    
    # Combined pattern for network calls
    local network_pattern='(fetch|https?\.get|https?\.request|http\.get|http\.request)\(["\x27]https?://[^"]+'
    local exclude_pattern='(npmjs\.org|registry\.npm|github\.com|githubusercontent\.com)'
    
    while read -r js_file; do
        while read -r match; do
            [ -z "$match" ] && continue
            
            local pkg_name=$(echo "$js_file" | sed -E 's|.*/node_modules/([^/]+)/.*|\1|')
            local line_num=$(echo "$match" | cut -d: -f1)
            
            log_warning "Suspicious network call in $pkg_name"
            echo "WARNING|$js_file|$pkg_name|$line_num|$match" >> "$NETWORK_CALLS"
            ((NETWORK_CALL_COUNT++)) || true
        done < <(grep -nE "$network_pattern" "$js_file" 2>/dev/null | grep -v -E "$exclude_pattern" | head -3 || true)
    done < <(find "$SCAN_PATH/node_modules" -type f \( -name "*.js" -o -name "*.mjs" \) 2>/dev/null | head -500)
    
    if [ "$NETWORK_CALL_COUNT" -eq 0 ]; then
        log_success "No suspicious network activity detected"
    fi
}

# 6. Check installation timing
check_installation_timing() {
    if [ "$PARANOID" = false ]; then
        return
    fi
    
    log_info "Checking installation timing..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would check node_modules modification times"
        return
    fi
    
    # PhantomRaven period: Aug 1 2025 to Oct 31 2025
    local aug_2025 oct_2025
    
    if [ "$OS_TYPE" = "macos" ]; then
        aug_2025=$(date -j -f "%Y-%m-%d" "2025-08-01" +%s 2>/dev/null || echo "0")
        oct_2025=$(date -j -f "%Y-%m-%d" "2025-10-31" +%s 2>/dev/null || echo "0")
    else
        aug_2025=$(date -d "2025-08-01" +%s 2>/dev/null || echo "0")
        oct_2025=$(date -d "2025-10-31" +%s 2>/dev/null || echo "0")
    fi
    
    if [ "$aug_2025" = "0" ] || [ "$oct_2025" = "0" ]; then
        log_warning "Could not parse dates for timing check"
        return
    fi
    
    while read -r nm_dir; do
        local mod_time=$(get_file_mtime "$nm_dir")
        
        if [ -n "$mod_time" ] && [ "$mod_time" != "0" ] && [ "$mod_time" -ge "$aug_2025" ] && [ "$mod_time" -le "$oct_2025" ]; then
            local mod_date=$(get_file_mtime_readable "$nm_dir")
            log_warning "Packages installed during PhantomRaven period: $nm_dir ($mod_date)"
            echo "WARNING|$nm_dir|$mod_date|PHANTOMRAVEN_PERIOD" >> "$TIMING_ISSUES"
            ((TIMING_SUSPICION_COUNT++)) || true
        fi
    done < <(find "$SCAN_PATH" -type d -name "node_modules" 2>/dev/null)
}

# 7. Scan for malicious domains (Optimized)
scan_for_malicious_domains() {
    log_info "Scanning for known malicious domains..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would scan for ${#MALICIOUS_DOMAINS[@]} malicious domains"
        return
    fi
    
    # Build combined pattern (escape special regex characters)
    local domain_pattern=""
    for domain in "${MALICIOUS_DOMAINS[@]}"; do
        # Escape dots for regex
        local escaped_domain=$(echo "$domain" | sed 's/\./\\./g')
        if [ -z "$domain_pattern" ]; then
            domain_pattern="$escaped_domain"
        else
            domain_pattern="$domain_pattern|$escaped_domain"
        fi
    done
    
    if [ -z "$domain_pattern" ]; then
        log_info "No malicious domains to scan for"
        return
    fi
    
    # Scan package.json files
    while read -r file; do
        if grep -E "$domain_pattern" "$file" 2>/dev/null > /dev/null; then
            log_critical "MALICIOUS DOMAIN FOUND in: $file"
            ((MALICIOUS_PKG_COUNT++)) || true
        fi
    done < <(find "$SCAN_PATH" -name "package.json" -type f 2>/dev/null)
    
    # Scan JS files in node_modules (limited)
    if [ -d "$SCAN_PATH/node_modules" ]; then
        if [ "$USE_PARALLEL" = true ]; then
            find "$SCAN_PATH/node_modules" -type f \( -name "*.js" -o -name "*.mjs" \) 2>/dev/null | \
            head -1000 | \
            parallel -j4 "grep -l -E '$domain_pattern' {} 2>/dev/null || true" | \
            while read -r file; do
                log_critical "MALICIOUS DOMAIN FOUND in: $file"
                ((MALICIOUS_PKG_COUNT++)) || true
            done
        else
            while read -r file; do
                if grep -E "$domain_pattern" "$file" 2>/dev/null > /dev/null; then
                    log_critical "MALICIOUS DOMAIN FOUND in: $file"
                    ((MALICIOUS_PKG_COUNT++)) || true
                    break
                fi
            done < <(find "$SCAN_PATH/node_modules" -type f \( -name "*.js" -o -name "*.mjs" \) 2>/dev/null | head -1000)
        fi
    fi
    
    # Scan project root JS/TS files
    while read -r file; do
        if grep -E "$domain_pattern" "$file" 2>/dev/null > /dev/null; then
            log_critical "MALICIOUS DOMAIN FOUND in: $file"
            ((MALICIOUS_PKG_COUNT++)) || true
        fi
    done < <(find "$SCAN_PATH" -maxdepth 3 -type f \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" \) 2>/dev/null)
}

# 8. Check system compromise
check_system_compromise() {
    if [ "$PARANOID" = false ]; then
        return
    fi
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would check system files for compromise"
        return
    fi
    
    echo ""
    log_info "═══════════════════════════════════════════════════"
    log_info "Running System Compromise Checks..."
    log_info "═══════════════════════════════════════════════════"
    
    # Check .gitconfig
    if [ -f "$HOME/.gitconfig" ]; then
        local mod_time=$(get_file_mtime_readable "$HOME/.gitconfig")
        log_info "~/.gitconfig last modified: $mod_time"
        
        local file_mod_epoch=$(get_file_mtime "$HOME/.gitconfig")
        
        local aug_2025 oct_2025
        if [ "$OS_TYPE" = "macos" ]; then
            aug_2025=$(date -j -f "%Y-%m-%d" "2025-08-01" +%s 2>/dev/null || echo "0")
            oct_2025=$(date -j -f "%Y-%m-%d" "2025-10-31" +%s 2>/dev/null || echo "0")
        else
            aug_2025=$(date -d "2025-08-01" +%s 2>/dev/null || echo "0")
            oct_2025=$(date -d "2025-10-31" +%s 2>/dev/null || echo "0")
        fi
        
        if [ -n "$file_mod_epoch" ] && [ "$file_mod_epoch" != "0" ] && \
           [ "$aug_2025" != "0" ] && [ "$oct_2025" != "0" ] && \
           [ "$file_mod_epoch" -ge "$aug_2025" ] && [ "$file_mod_epoch" -le "$oct_2025" ]; then
            log_warning "⚠ .gitconfig was modified during PhantomRaven active period!"
        fi
    fi
    
    # Check .npmrc
    if [ -f "$HOME/.npmrc" ]; then
        local mod_time=$(get_file_mtime_readable "$HOME/.npmrc")
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

generate_json_report() {
    local severity="clean"
    if [ "$MALICIOUS_PKG_COUNT" -gt 0 ] || ([ "$RDD_COUNT" -gt 0 ] && [ -f "$RDD_FINDINGS" ] && grep -q "CRITICAL" "$RDD_FINDINGS" 2>/dev/null); then
        severity="critical"
    elif [ "$RDD_COUNT" -gt 0 ] || [ "$SUSPICIOUS_SCRIPT_COUNT" -gt 0 ]; then
        severity="warning"
    fi
    
    local scan_duration=$(($(date +%s) - SCAN_START_TIME))
    
    # Build findings arrays with proper error handling
    local rdd_findings="[]"
    if [ -f "$RDD_FINDINGS" ] && [ -s "$RDD_FINDINGS" ]; then
        rdd_findings=$(while IFS='|' read -r sev file pkg url status; do
            [ -z "$sev" ] && continue
            jq -n \
                --arg severity "$sev" \
                --arg file "$file" \
                --arg package "$pkg" \
                --arg url "$url" \
                --arg status "$status" \
                '{severity: $severity, file: $file, package: $package, url: $url, status: $status}'
        done < "$RDD_FINDINGS" | jq -s '.' 2>/dev/null || echo "[]")
    fi
    
    local malicious_findings="[]"
    if [ -f "$MALICIOUS_FINDINGS" ] && [ -s "$MALICIOUS_FINDINGS" ]; then
        malicious_findings=$(while IFS='|' read -r sev file pkg version; do
            [ -z "$sev" ] && continue
            jq -n \
                --arg severity "$sev" \
                --arg file "$file" \
                --arg package "$pkg" \
                --arg version "$version" \
                '{severity: $severity, file: $file, package: $package, version: $version}'
        done < "$MALICIOUS_FINDINGS" | jq -s '.' 2>/dev/null || echo "[]")
    fi

    local suspicious_script_findings="[]"
    if [ -f "$SUSPICIOUS_SCRIPTS" ] && [ -s "$SUSPICIOUS_SCRIPTS" ]; then
        suspicious_script_findings=$(
            while IFS='|' read -r sev file pkg script content extra; do
                [ -z "$sev" ] && continue
                local note="${extra:-}"
                jq -n \
                    --arg severity "$sev" \
                    --arg file "$file" \
                    --arg package "$pkg" \
                    --arg script "$script" \
                    --arg content "$content" \
                    --arg note "$note" \
                    '{
                        severity: $severity,
                        file: $file,
                        package: $package,
                        script: $script,
                        content: $content
                    } + (if $note != "" then {note: $note} else {} end)'
            done < "$SUSPICIOUS_SCRIPTS" | jq -s '.' 2>/dev/null || echo "[]"
        )
    fi

    local credential_theft_findings="[]"
    if [ -f "$CREDENTIAL_THEFT" ] && [ -s "$CREDENTIAL_THEFT" ]; then
        credential_theft_findings=$(
            while IFS='|' read -r sev file pkg pattern; do
                [ -z "$sev" ] && continue
                jq -n \
                    --arg severity "$sev" \
                    --arg file "$file" \
                    --arg package "$pkg" \
                    --arg pattern "$pattern" \
                    '{severity: $severity, file: $file, package: $package, pattern: $pattern}'
            done < "$CREDENTIAL_THEFT" | jq -s '.' 2>/dev/null || echo "[]"
        )
    fi

    local network_call_findings="[]"
    if [ -f "$NETWORK_CALLS" ] && [ -s "$NETWORK_CALLS" ]; then
        network_call_findings=$(
            while IFS='|' read -r sev file pkg line_num snippet; do
                [ -z "$sev" ] && continue
                jq -n \
                    --arg severity "$sev" \
                    --arg file "$file" \
                    --arg package "$pkg" \
                    --arg line "$line_num" \
                    --arg snippet "$snippet" \
                    '{severity: $severity, file: $file, package: $package, line: $line, snippet: $snippet}'
            done < "$NETWORK_CALLS" | jq -s '.' 2>/dev/null || echo "[]"
        )
    fi

    local timing_issue_findings="[]"
    if [ -f "$TIMING_ISSUES" ] && [ -s "$TIMING_ISSUES" ]; then
        timing_issue_findings=$(
            while IFS='|' read -r sev path timestamp reason; do
                [ -z "$sev" ] && continue
                jq -n \
                    --arg severity "$sev" \
                    --arg path "$path" \
                    --arg timestamp "$timestamp" \
                    --arg reason "$reason" \
                    '{severity: $severity, path: $path, timestamp: $timestamp, reason: $reason}'
            done < "$TIMING_ISSUES" | jq -s '.' 2>/dev/null || echo "[]"
        )
    fi

    local error_messages="[]"
    if [ -f "$ERROR_LOG" ] && [ -s "$ERROR_LOG" ]; then
        error_messages=$(jq -Rs 'split("\n") | map(select(length > 0))' "$ERROR_LOG" 2>/dev/null || echo "[]")
    fi
    
    jq -n \
        --arg version "$VERSION" \
        --arg scan_path "$SCAN_PATH" \
        --arg severity "$severity" \
        --arg timestamp "$(date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S)" \
        --arg duration "$scan_duration" \
        --arg files_scanned "$FILES_SCANNED" \
        --arg rdd_count "$RDD_COUNT" \
        --arg malicious_count "$MALICIOUS_PKG_COUNT" \
        --arg suspicious_scripts "$SUSPICIOUS_SCRIPT_COUNT" \
        --arg credential_theft "$CREDENTIAL_THEFT_COUNT" \
        --arg network_calls "$NETWORK_CALL_COUNT" \
        --arg timing_suspicions "$TIMING_SUSPICION_COUNT" \
        --argjson rdd_findings "$rdd_findings" \
        --argjson malicious_findings "$malicious_findings" \
        --argjson suspicious_script_findings "$suspicious_script_findings" \
        --argjson credential_theft_findings "$credential_theft_findings" \
        --argjson network_call_findings "$network_call_findings" \
        --argjson timing_issue_findings "$timing_issue_findings" \
        --argjson errors "$error_messages" \
        '{
            version: $version,
            timestamp: $timestamp,
            scan_path: $scan_path,
            duration_seconds: ($duration | tonumber),
            files_scanned: ($files_scanned | tonumber),
            severity: $severity,
            summary: {
                rdd_count: ($rdd_count | tonumber),
                malicious_packages: ($malicious_count | tonumber),
                suspicious_scripts: ($suspicious_scripts | tonumber),
                credential_theft_patterns: ($credential_theft | tonumber),
                suspicious_network_calls: ($network_calls | tonumber),
                timing_suspicions: ($timing_suspicions | tonumber)
            },
            findings: {
                remote_dynamic_dependencies: $rdd_findings,
                malicious_packages: $malicious_findings,
                suspicious_scripts: $suspicious_script_findings,
                credential_theft: $credential_theft_findings,
                network_calls: $network_call_findings,
                timing_anomalies: $timing_issue_findings
            },
            errors: $errors
        }'
    
    local exit_code=0
    if [ "$severity" = "critical" ]; then
        exit_code=1
    elif [ "$severity" = "warning" ]; then
        exit_code=2
    fi
    
    return $exit_code
}

generate_report() {
    if [ "$JSON_OUTPUT" = true ]; then
        generate_json_report
        return
    fi
    
    local scan_duration=$(($(date +%s) - SCAN_START_TIME))
    
    echo ""
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}                    SCAN RESULTS                           ${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Performance stats
    echo -e "${BOLD}Performance:${NC}"
    echo "├─ Scan Duration: ${scan_duration}s"
    echo "└─ Files Scanned: $FILES_SCANNED"
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
            [ -z "$severity" ] && continue
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
            [ -z "$severity" ] && continue
            echo -e "${RED}[CRITICAL]${NC} $pkg@$version"
            echo "  File: $file"
            echo ""
        done < "$MALICIOUS_FINDINGS"
    fi
    
    if [ -s "$SUSPICIOUS_SCRIPTS" ]; then
        echo -e "${YELLOW}⚠ Suspicious Lifecycle Scripts:${NC}"
        echo "════════════════════════════════════════"
        head -20 "$SUSPICIOUS_SCRIPTS" | while IFS='|' read -r severity file pkg script content extra; do
            [ -z "$severity" ] && continue
            echo -e "${YELLOW}[WARNING]${NC} $pkg - $script"
            echo "  File: $file"
            echo "  Content: $content"
            [ -n "$extra" ] && echo "  Note: $extra"
            echo ""
        done
        
        local line_count=$(wc -l < "$SUSPICIOUS_SCRIPTS" 2>/dev/null | tr -d ' ' || echo "0")
        if [ "$line_count" -gt 20 ]; then
            echo "... and $((line_count - 20)) more"
            echo ""
        fi
    fi
    
    # Errors log
    if [ -s "$ERROR_LOG" ]; then
        echo -e "${YELLOW}⚠ Errors encountered during scan:${NC}"
        head -10 "$ERROR_LOG"
        echo ""
    fi
    
    # Final verdict
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    if [ "$MALICIOUS_PKG_COUNT" -gt 0 ] || \
       ([ "$RDD_COUNT" -gt 0 ] && [ -f "$RDD_FINDINGS" ] && grep -q "CRITICAL" "$RDD_FINDINGS" 2>/dev/null); then
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
        
        return 1
    elif [ "$RDD_COUNT" -gt 0 ] || [ "$SUSPICIOUS_SCRIPT_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}${BOLD}⚠ WARNING: Suspicious indicators found${NC}"
        echo ""
        echo "RECOMMENDED ACTIONS:"
        echo "1. Review the findings above carefully"
        echo "2. Verify all flagged packages are legitimate"
        echo "3. Consider rotating credentials as a precaution"
        echo "4. Run with --paranoid flag for deeper analysis"
        
        return 2
    else
        echo -e "${GREEN}${BOLD}✓ No critical threats detected${NC}"
        echo ""
        echo "Your npm projects appear clean based on known PhantomRaven indicators."
        echo ""
        if [ "$DEEP_SCAN" = false ]; then
            echo "💡 Tip: Run with --deep or --paranoid for more thorough scanning"
        fi
        
        return 0
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
            --json)
                JSON_OUTPUT=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --no-cache)
                USE_CACHE=false
                shift
                ;;
            --parallel)
                USE_PARALLEL=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --version)
                echo "PhantomRaven Hunter v${VERSION}"
                exit 0
                ;;
            -*)
                log_error "Unknown option: $1"
                echo ""
                echo "Use --help to see available options"
                exit 1
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
    SCAN_START_TIME=$(date +%s)
    
    parse_arguments "$@"
    
    print_banner
    
    local target_stream=1
    if [ "$JSON_OUTPUT" = true ]; then
        target_stream=2
    fi
    
    echo -e "${BOLD}Configuration:${NC}" >&$target_stream
    echo "  Scan Path:      $SCAN_PATH" >&$target_stream
    echo "  Deep Scan:      $DEEP_SCAN" >&$target_stream
    echo "  Paranoid Mode:  $PARANOID" >&$target_stream
    echo "  Verbose:        $VERBOSE" >&$target_stream
    echo "  JSON Output:    $JSON_OUTPUT" >&$target_stream
    echo "  Dry Run:        $DRY_RUN" >&$target_stream
    echo "  Use Cache:      $USE_CACHE" >&$target_stream
    echo "  Parallel:       $USE_PARALLEL" >&$target_stream
    echo "" >&$target_stream
    
    # Validation
    validate_dependencies
    validate_scan_path
    validate_data_files
    
    if [ "$DRY_RUN" = true ]; then
        log_info "DRY RUN MODE - No actual scanning will be performed"
        log_info "The following checks would be executed:"
        echo "  ✓ Remote Dynamic Dependencies" >&$target_stream
        echo "  ✓ Known Malicious Packages" >&$target_stream
        echo "  ✓ Lifecycle Scripts Analysis" >&$target_stream
        echo "  ✓ Malicious Domain Scan" >&$target_stream
        [ "$DEEP_SCAN" = true ] && echo "  ✓ Credential Theft Patterns" >&$target_stream
        [ "$DEEP_SCAN" = true ] && echo "  ✓ Network Activity" >&$target_stream
        [ "$PARANOID" = true ] && echo "  ✓ Installation Timing" >&$target_stream
        [ "$PARANOID" = true ] && echo "  ✓ System Compromise" >&$target_stream
        exit 0
    fi
    
    # Load external data files
    load_all_data
    
    # Count total files for progress
    TOTAL_FILES=$(find "$SCAN_PATH" -name "package.json" -type f 2>/dev/null | wc -l | tr -d ' ')
    
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
    
    # Generate report and capture exit code
    set +e
    generate_report
    local exit_code=$?
    set -e
    
    exit $exit_code
}

# Run main
main "$@"
