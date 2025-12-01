#!/bin/bash

#############################################################################
# npm-threat-hunter - Comprehensive NPM Supply Chain Malware Detection
#
# A shell-based scanner for detecting npm supply chain attacks including
# PhantomRaven, Shai-Hulud 2.0, and similar threats.
#
# Usage: ./npm-threat-hunter.sh [OPTIONS] [PATH]
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
# Supported Campaigns:
#   - PhantomRaven (Aug-Oct 2025)
#   - Shai-Hulud 2.0 (Nov 2025 - ONGOING)
#
# Repository: https://github.com/paoloanzn/npm-threat-hunter
# License: MIT
# Version: 2.0.0
#############################################################################

set -e
# Note: pipefail disabled to allow grep failures in pipes without script exit
# set -o pipefail

#############################################################################
# Configuration & Constants
#############################################################################

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly VERSION="2.0.0"

# Data files (external configuration)
readonly DATA_DIR="${SCRIPT_DIR}/data"
readonly MALICIOUS_PACKAGES_FILE="${DATA_DIR}/malicious-packages.txt"
readonly MALICIOUS_DOMAINS_FILE="${DATA_DIR}/malicious-domains.txt"
readonly SAFE_DOMAINS_FILE="${DATA_DIR}/safe-domains.txt"
readonly SAFE_PACKAGES_FILE="${DATA_DIR}/safe-packages.txt"
readonly IOC_ARTIFACTS_FILE="${DATA_DIR}/ioc-artifacts.txt"

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
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# Findings counters
RDD_COUNT=0
MALICIOUS_PKG_COUNT=0
SUSPICIOUS_SCRIPT_COUNT=0
CREDENTIAL_THEFT_COUNT=0
NETWORK_CALL_COUNT=0
TIMING_SUSPICION_COUNT=0
SHAI_HULUD_ARTIFACT_COUNT=0
WORKFLOW_INJECTION_COUNT=0
VERSION_MATCH_COUNT=0

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
readonly SHAI_HULUD_FINDINGS="${TMP_DIR}/shai_hulud_findings.txt"
readonly WORKFLOW_FINDINGS="${TMP_DIR}/workflow_findings.txt"
readonly VERSION_FINDINGS="${TMP_DIR}/version_findings.txt"
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
    local files_to_hash=""
    [ -f "$MALICIOUS_PACKAGES_FILE" ] && files_to_hash="$files_to_hash $MALICIOUS_PACKAGES_FILE"
    [ -f "$MALICIOUS_DOMAINS_FILE" ] && files_to_hash="$files_to_hash $MALICIOUS_DOMAINS_FILE"
    [ -f "$SAFE_DOMAINS_FILE" ] && files_to_hash="$files_to_hash $SAFE_DOMAINS_FILE"
    [ -f "$SAFE_PACKAGES_FILE" ] && files_to_hash="$files_to_hash $SAFE_PACKAGES_FILE"
    [ -f "$IOC_ARTIFACTS_FILE" ] && files_to_hash="$files_to_hash $IOC_ARTIFACTS_FILE"
    
    if command -v sha256sum &> /dev/null; then
        cat $files_to_hash 2>/dev/null | sha256sum | cut -d' ' -f1
    elif command -v shasum &> /dev/null; then
        cat $files_to_hash 2>/dev/null | shasum -a 256 | cut -d' ' -f1
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

load_ioc_artifacts() {
    if [ ! -f "$IOC_ARTIFACTS_FILE" ]; then
        log_warning "IOC artifacts file not found: $IOC_ARTIFACTS_FILE"
        return
    fi
    
    # Initialize arrays
    IOC_FILES=()
    IOC_WORKFLOWS=()
    IOC_CODE_PATTERNS=()
    IOC_VERSIONS=()
    IOC_NAMESPACES=()
    
    while IFS='|' read -r type pattern description campaign; do
        # Skip comments and empty lines
        [[ "$type" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${type// }" ]] && continue
        
        case "$type" in
            FILE)
                IOC_FILES+=("$pattern|$description|$campaign")
                ;;
            WORKFLOW)
                IOC_WORKFLOWS+=("$pattern|$description|$campaign")
                ;;
            CODE_PATTERN)
                IOC_CODE_PATTERNS+=("$pattern|$description|$campaign")
                ;;
            VERSION)
                IOC_VERSIONS+=("$pattern|$description|$campaign")
                ;;
            NAMESPACE)
                IOC_NAMESPACES+=("$pattern|$description|$campaign")
                ;;
        esac
    done < "$IOC_ARTIFACTS_FILE"
    
    log_info "Loaded ${#IOC_FILES[@]} IOC files, ${#IOC_WORKFLOWS[@]} workflow patterns, ${#IOC_VERSIONS[@]} version IOCs, ${#IOC_NAMESPACES[@]} namespace patterns"
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
    
    # Always load IOC artifacts (not cached for now)
    load_ioc_artifacts
    
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

log_campaign() {
    local campaign="$1"
    local message="$2"
    local color="$MAGENTA"
    
    if [ "$JSON_OUTPUT" = true ]; then
        echo -e "${color}[${campaign}]${NC} $message" >&2
    else
        echo -e "${color}[${campaign}]${NC} $message"
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
║              npm-threat-hunter v2.0.0                     ║
║        Comprehensive Supply Chain Attack Detection        ║
║                                                           ║
║   Campaigns: PhantomRaven | Shai-Hulud 2.0 | and more     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}" >&$target_stream
}

show_help() {
    cat << EOF
npm-threat-hunter v${VERSION}
Detect npm supply chain attacks including PhantomRaven, Shai-Hulud 2.0, and more

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

SUPPORTED CAMPAIGNS:
    - PhantomRaven (Aug-Oct 2025) - RDD-based attacks
    - Shai-Hulud 2.0 (Nov 2025+)  - GitHub Actions exploitation

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

REPOSITORY:
    https://github.com/paoloanzn/npm-threat-hunter

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
    
    # IOC artifacts file is optional but recommended
    if [ ! -f "$IOC_ARTIFACTS_FILE" ]; then
        log_warning "IOC artifacts file not found: $IOC_ARTIFACTS_FILE"
        log_warning "Shai-Hulud 2.0 specific detection will be limited"
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

# 2. Check for known malicious packages (Enhanced with namespace support)
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
        
        # Get all dependencies from the file
        local deps=$(safe_jq '
            ((.dependencies // {}) + 
            (.devDependencies // {}) + 
            (.peerDependencies // {}) + 
            (.optionalDependencies // {})) | 
            to_entries[] | 
            "\(.key)|\(.value)"
        ' "$pkg_file" 2>/dev/null || true)
        
        while IFS='|' read -r dep_name dep_version; do
            [ -z "$dep_name" ] && continue
            
            # Check exact package match
            for malicious_pkg in "${MALICIOUS_PACKAGES[@]}"; do
                # Handle namespace prefixes (e.g., @trigo/)
                if [[ "$malicious_pkg" == */ ]]; then
                    # This is a namespace prefix
                    if [[ "$dep_name" == ${malicious_pkg}* ]]; then
                        log_critical "MALICIOUS NAMESPACE PACKAGE: $dep_name@$dep_version"
                        log_campaign "SHAI_HULUD_2" "Package under compromised namespace: $malicious_pkg"
                        echo "CRITICAL|$pkg_file|$dep_name|$dep_version|NAMESPACE_MATCH|$malicious_pkg" >> "$MALICIOUS_FINDINGS"
                        ((MALICIOUS_PKG_COUNT++)) || true
                    fi
                elif [ "$dep_name" = "$malicious_pkg" ]; then
                    log_critical "KNOWN MALICIOUS PACKAGE: $dep_name@$dep_version"
                    echo "CRITICAL|$pkg_file|$dep_name|$dep_version|EXACT_MATCH" >> "$MALICIOUS_FINDINGS"
                    ((MALICIOUS_PKG_COUNT++)) || true
                fi
            done
        done <<< "$deps"
        
        ((FILES_SCANNED++)) || true
    done
    
    clear_progress
    
    if [ "$MALICIOUS_PKG_COUNT" -eq 0 ]; then
        log_success "No known malicious packages found"
    else
        log_critical "Found $MALICIOUS_PKG_COUNT known malicious packages!"
    fi
}

# 3. Check for specific compromised versions (Shai-Hulud 2.0)
detect_compromised_versions() {
    log_info "Checking for specific compromised package versions..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would check for ${#IOC_VERSIONS[@]} compromised versions"
        return
    fi
    
    if [ ${#IOC_VERSIONS[@]} -eq 0 ]; then
        log_info "No version-specific IOCs loaded, skipping"
        return
    fi
    
    local pkg_files=()
    while IFS= read -r file; do
        pkg_files+=("$file")
    done < <(find "$SCAN_PATH" -name "package.json" -type f 2>/dev/null)
    
    for pkg_file in "${pkg_files[@]}"; do
        # Also check package-lock.json for exact versions
        local lock_file="${pkg_file%.json}-lock.json"
        
        for version_ioc in "${IOC_VERSIONS[@]}"; do
            IFS='|' read -r pkg_name versions campaign <<< "$version_ioc"
            
            # Check if package exists in dependencies
            local installed_version=$(safe_jq --arg pkg "$pkg_name" '
                ((.dependencies // {}) + 
                (.devDependencies // {}) + 
                (.peerDependencies // {}) + 
                (.optionalDependencies // {}))[$pkg] // empty
            ' "$pkg_file" 2>/dev/null || true)
            
            if [ -n "$installed_version" ]; then
                # Check if the version matches any compromised version
                IFS=',' read -ra version_array <<< "$versions"
                for bad_version in "${version_array[@]}"; do
                    # Clean whitespace
                    bad_version=$(echo "$bad_version" | tr -d ' ')
                    
                    # Check exact match or semver match
                    if [[ "$installed_version" == "$bad_version" ]] || \
                       [[ "$installed_version" == "^$bad_version" ]] || \
                       [[ "$installed_version" == "~$bad_version" ]]; then
                        log_critical "COMPROMISED VERSION DETECTED: $pkg_name@$bad_version"
                        log_campaign "$campaign" "Exact compromised version match!"
                        echo "CRITICAL|$pkg_file|$pkg_name|$bad_version|$campaign" >> "$VERSION_FINDINGS"
                        ((VERSION_MATCH_COUNT++)) || true
                    fi
                done
            fi
        done
    done
    
    if [ "$VERSION_MATCH_COUNT" -eq 0 ]; then
        log_success "No compromised versions detected"
    else
        log_critical "Found $VERSION_MATCH_COUNT packages with known compromised versions!"
    fi
}

# 4. Detect Shai-Hulud 2.0 artifact files
detect_shai_hulud_artifacts() {
    log_info "Scanning for Shai-Hulud 2.0 artifacts..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would scan for Shai-Hulud payload files"
        return
    fi
    
    if [ ${#IOC_FILES[@]} -eq 0 ]; then
        log_info "No IOC file patterns loaded, skipping"
        return
    fi
    
    for file_ioc in "${IOC_FILES[@]}"; do
        IFS='|' read -r filename description campaign <<< "$file_ioc"
        
        # Search for the file
        while read -r found_file; do
            log_critical "SHAI-HULUD ARTIFACT FOUND: $found_file"
            log_campaign "$campaign" "$description"
            echo "CRITICAL|$found_file|$filename|$description|$campaign" >> "$SHAI_HULUD_FINDINGS"
            ((SHAI_HULUD_ARTIFACT_COUNT++)) || true
        done < <(find "$SCAN_PATH" -name "$filename" -type f 2>/dev/null)
    done
    
    if [ "$SHAI_HULUD_ARTIFACT_COUNT" -eq 0 ]; then
        log_success "No Shai-Hulud artifacts found"
    else
        log_critical "Found $SHAI_HULUD_ARTIFACT_COUNT Shai-Hulud artifacts!"
    fi
}

# 5. Scan GitHub Actions workflows for injection
detect_workflow_injections() {
    log_info "Scanning GitHub Actions workflows for injections..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would scan .github/workflows for malicious patterns"
        return
    fi
    
    # Find all workflow directories
    local workflow_dirs=()
    while IFS= read -r dir; do
        workflow_dirs+=("$dir")
    done < <(find "$SCAN_PATH" -type d -name "workflows" -path "*/.github/*" 2>/dev/null)
    
    if [ ${#workflow_dirs[@]} -eq 0 ]; then
        log_info "No GitHub Actions workflow directories found"
        return
    fi
    
    log_info "Found ${#workflow_dirs[@]} workflow directory(ies)"
    
    for workflow_dir in "${workflow_dirs[@]}"; do
        # Check for known malicious workflow names
        for workflow_ioc in "${IOC_WORKFLOWS[@]}"; do
            IFS='|' read -r pattern description campaign <<< "$workflow_ioc"
            
            while read -r found_workflow; do
                log_critical "MALICIOUS WORKFLOW DETECTED: $found_workflow"
                log_campaign "$campaign" "$description"
                echo "CRITICAL|$found_workflow|$pattern|$description|$campaign" >> "$WORKFLOW_FINDINGS"
                ((WORKFLOW_INJECTION_COUNT++)) || true
            done < <(find "$workflow_dir" -name "$pattern" -type f 2>/dev/null)
        done
        
        # Scan workflow content for injection patterns
        while read -r workflow_file; do
            # Check for Shai-Hulud specific patterns
            
            # 1. Self-hosted runner with discussion trigger (backdoor pattern)
            if grep -q "runs-on: self-hosted" "$workflow_file" 2>/dev/null && \
               grep -q "discussion:" "$workflow_file" 2>/dev/null; then
                log_critical "BACKDOOR PATTERN: Self-hosted runner with discussion trigger"
                log_campaign "SHAI_HULUD_2" "Potential command injection via discussions"
                echo "CRITICAL|$workflow_file|discussion+self-hosted|Backdoor pattern|SHAI_HULUD_2" >> "$WORKFLOW_FINDINGS"
                ((WORKFLOW_INJECTION_COUNT++)) || true
            fi
            
            # 2. Secret enumeration pattern
            if grep -qE 'toJSON\(secrets\)' "$workflow_file" 2>/dev/null; then
                log_critical "SECRET EXFILTRATION: toJSON(secrets) found"
                log_campaign "SHAI_HULUD_2" "Workflow attempts to enumerate all secrets"
                echo "CRITICAL|$workflow_file|toJSON(secrets)|Secret enumeration|SHAI_HULUD_2" >> "$WORKFLOW_FINDINGS"
                ((WORKFLOW_INJECTION_COUNT++)) || true
            fi
            
            # 3. Command injection via event body
            if grep -qE 'echo \$\{\{.*\.(body|title|comment)\s*\}\}' "$workflow_file" 2>/dev/null; then
                log_critical "COMMAND INJECTION: Unsafe echo of event data"
                log_campaign "SHAI_HULUD_2" "Workflow vulnerable to command injection"
                echo "CRITICAL|$workflow_file|unsafe-echo|Command injection|SHAI_HULUD_2" >> "$WORKFLOW_FINDINGS"
                ((WORKFLOW_INJECTION_COUNT++)) || true
            fi
            
            # 4. Suspicious artifact upload after secret access
            if grep -q "upload-artifact" "$workflow_file" 2>/dev/null && \
               grep -qE '(secrets|\.json)' "$workflow_file" 2>/dev/null; then
                log_warning "Suspicious: Artifact upload with potential secret access"
                echo "WARNING|$workflow_file|artifact-upload|Potential secret exfil|SHAI_HULUD_2" >> "$WORKFLOW_FINDINGS"
                ((WORKFLOW_INJECTION_COUNT++)) || true
            fi
            
        done < <(find "$workflow_dir" -name "*.yml" -o -name "*.yaml" 2>/dev/null)
    done
    
    if [ "$WORKFLOW_INJECTION_COUNT" -eq 0 ]; then
        log_success "No workflow injections detected"
    else
        log_critical "Found $WORKFLOW_INJECTION_COUNT workflow security issues!"
    fi
}

# 6. Analyze lifecycle scripts
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
            
            # Shai-Hulud specific: Check for bun/setup references
            if echo "$script_content" | grep -iE '(setup_bun|bun_environment|octokit|self-hosted)' > /dev/null 2>&1; then
                log_critical "SHAI-HULUD PATTERN in lifecycle script: $pkg_name"
                log_campaign "SHAI_HULUD_2" "Script contains Shai-Hulud indicators"
                echo "CRITICAL|$pkg_file|$pkg_name|$script_name|$script_content|SHAI_HULUD_PATTERN" >> "$SUSPICIOUS_SCRIPTS"
                ((SUSPICIOUS_SCRIPT_COUNT++)) || true
            fi
            
        done < <(safe_jq '.scripts // {} | to_entries[] | select(.key | test("(pre|post)?install")) | "\(.key)|\(.value)"' "$pkg_file" 2>/dev/null || true)
        
        ((FILES_SCANNED++)) || true
    done
    
    clear_progress
    
    if [ "$SUSPICIOUS_SCRIPT_COUNT" -eq 0 ]; then
        log_success "No suspicious lifecycle scripts found"
    fi
}

# 7. Deep scan for credential theft patterns (Optimized)
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
    
    # Build combined grep pattern (including Shai-Hulud patterns)
    local pattern_string="NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|CI_TOKEN|process\.env\.|toJSON\(secrets\)|self-hosted|SHA1HULUD"
    
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

# 8. Scan for network activity (Optimized)
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
            
            # Check for webhook.site (Shai-Hulud exfil)
            if echo "$match" | grep -q "webhook.site" 2>/dev/null; then
                log_critical "EXFILTRATION ENDPOINT: webhook.site detected!"
                log_campaign "SHAI_HULUD_2" "Known exfiltration endpoint"
                echo "CRITICAL|$js_file|$pkg_name|$line_num|$match|SHAI_HULUD_EXFIL" >> "$NETWORK_CALLS"
            else
                log_warning "Suspicious network call in $pkg_name"
                echo "WARNING|$js_file|$pkg_name|$line_num|$match" >> "$NETWORK_CALLS"
            fi
            ((NETWORK_CALL_COUNT++)) || true
        done < <(grep -nE "$network_pattern" "$js_file" 2>/dev/null | grep -v -E "$exclude_pattern" | head -3 || true)
    done < <(find "$SCAN_PATH/node_modules" -type f \( -name "*.js" -o -name "*.mjs" \) 2>/dev/null | head -500)
    
    if [ "$NETWORK_CALL_COUNT" -eq 0 ]; then
        log_success "No suspicious network activity detected"
    fi
}

# 9. Check installation timing (Updated with Shai-Hulud period)
check_installation_timing() {
    if [ "$PARANOID" = false ]; then
        return
    fi
    
    log_info "Checking installation timing..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would check node_modules modification times"
        return
    fi
    
    # Attack periods
    local phantomraven_start phantomraven_end
    local shaihulud_start shaihulud_end
    
    if [ "$OS_TYPE" = "macos" ]; then
        phantomraven_start=$(date -j -f "%Y-%m-%d" "2025-08-01" +%s 2>/dev/null || echo "0")
        phantomraven_end=$(date -j -f "%Y-%m-%d" "2025-10-31" +%s 2>/dev/null || echo "0")
        shaihulud_start=$(date -j -f "%Y-%m-%d" "2025-11-21" +%s 2>/dev/null || echo "0")
        shaihulud_end=$(date -j -f "%Y-%m-%d" "2025-11-30" +%s 2>/dev/null || echo "0")
    else
        phantomraven_start=$(date -d "2025-08-01" +%s 2>/dev/null || echo "0")
        phantomraven_end=$(date -d "2025-10-31" +%s 2>/dev/null || echo "0")
        shaihulud_start=$(date -d "2025-11-21" +%s 2>/dev/null || echo "0")
        shaihulud_end=$(date -d "2025-11-30" +%s 2>/dev/null || echo "0")
    fi
    
    if [ "$phantomraven_start" = "0" ]; then
        log_warning "Could not parse dates for timing check"
        return
    fi
    
    while read -r nm_dir; do
        local mod_time=$(get_file_mtime "$nm_dir")
        local mod_date=$(get_file_mtime_readable "$nm_dir")
        
        if [ -z "$mod_time" ] || [ "$mod_time" = "0" ]; then
            continue
        fi
        
        # Check PhantomRaven period (Aug-Oct 2025)
        if [ "$mod_time" -ge "$phantomraven_start" ] && [ "$mod_time" -le "$phantomraven_end" ]; then
            log_warning "Packages installed during PhantomRaven period: $nm_dir ($mod_date)"
            echo "WARNING|$nm_dir|$mod_date|PHANTOMRAVEN_PERIOD" >> "$TIMING_ISSUES"
            ((TIMING_SUSPICION_COUNT++)) || true
        fi
        
        # Check Shai-Hulud period (Nov 21-30, 2025)
        if [ "$mod_time" -ge "$shaihulud_start" ] && [ "$mod_time" -le "$shaihulud_end" ]; then
            log_critical "Packages installed during Shai-Hulud 2.0 active period!"
            log_campaign "SHAI_HULUD_2" "Installation during Nov 21-30, 2025"
            echo "CRITICAL|$nm_dir|$mod_date|SHAI_HULUD_PERIOD" >> "$TIMING_ISSUES"
            ((TIMING_SUSPICION_COUNT++)) || true
        fi
        
    done < <(find "$SCAN_PATH" -type d -name "node_modules" 2>/dev/null)
}

# 10. Scan for malicious domains (Optimized)
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

# 11. Check system compromise
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
        
        local phantomraven_start phantomraven_end shaihulud_start shaihulud_end
        if [ "$OS_TYPE" = "macos" ]; then
            phantomraven_start=$(date -j -f "%Y-%m-%d" "2025-08-01" +%s 2>/dev/null || echo "0")
            phantomraven_end=$(date -j -f "%Y-%m-%d" "2025-10-31" +%s 2>/dev/null || echo "0")
            shaihulud_start=$(date -j -f "%Y-%m-%d" "2025-11-21" +%s 2>/dev/null || echo "0")
            shaihulud_end=$(date -j -f "%Y-%m-%d" "2025-11-30" +%s 2>/dev/null || echo "0")
        else
            phantomraven_start=$(date -d "2025-08-01" +%s 2>/dev/null || echo "0")
            phantomraven_end=$(date -d "2025-10-31" +%s 2>/dev/null || echo "0")
            shaihulud_start=$(date -d "2025-11-21" +%s 2>/dev/null || echo "0")
            shaihulud_end=$(date -d "2025-11-30" +%s 2>/dev/null || echo "0")
        fi
        
        if [ -n "$file_mod_epoch" ] && [ "$file_mod_epoch" != "0" ]; then
            if [ "$phantomraven_start" != "0" ] && \
               [ "$file_mod_epoch" -ge "$phantomraven_start" ] && [ "$file_mod_epoch" -le "$phantomraven_end" ]; then
                log_warning "⚠ .gitconfig was modified during PhantomRaven active period!"
            fi
            if [ "$shaihulud_start" != "0" ] && \
               [ "$file_mod_epoch" -ge "$shaihulud_start" ] && [ "$file_mod_epoch" -le "$shaihulud_end" ]; then
                log_critical "⚠ .gitconfig was modified during Shai-Hulud 2.0 active period!"
                log_campaign "SHAI_HULUD_2" "System config modification detected"
            fi
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
    
    # Check for Shai-Hulud self-hosted runner registration
    if command -v gh &> /dev/null; then
        log_info "Checking for suspicious GitHub self-hosted runners..."
        if gh api user/repos --jq '.[].name' 2>/dev/null | head -5 | while read -r repo; do
            if gh api "repos/$repo/actions/runners" 2>/dev/null | grep -q "SHA1HULUD"; then
                log_critical "SHAI-HULUD RUNNER DETECTED in repo: $repo"
                return 1
            fi
        done; then
            :
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
    if [ "$MALICIOUS_PKG_COUNT" -gt 0 ] || \
       [ "$VERSION_MATCH_COUNT" -gt 0 ] || \
       [ "$SHAI_HULUD_ARTIFACT_COUNT" -gt 0 ] || \
       [ "$WORKFLOW_INJECTION_COUNT" -gt 0 ] || \
       ([ "$RDD_COUNT" -gt 0 ] && [ -f "$RDD_FINDINGS" ] && grep -q "CRITICAL" "$RDD_FINDINGS" 2>/dev/null); then
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
        malicious_findings=$(while IFS='|' read -r sev file pkg version match_type extra; do
            [ -z "$sev" ] && continue
            jq -n \
                --arg severity "$sev" \
                --arg file "$file" \
                --arg package "$pkg" \
                --arg version "$version" \
                --arg match_type "$match_type" \
                '{severity: $severity, file: $file, package: $package, version: $version, match_type: $match_type}'
        done < "$MALICIOUS_FINDINGS" | jq -s '.' 2>/dev/null || echo "[]")
    fi
    
    local version_findings="[]"
    if [ -f "$VERSION_FINDINGS" ] && [ -s "$VERSION_FINDINGS" ]; then
        version_findings=$(while IFS='|' read -r sev file pkg version campaign; do
            [ -z "$sev" ] && continue
            jq -n \
                --arg severity "$sev" \
                --arg file "$file" \
                --arg package "$pkg" \
                --arg version "$version" \
                --arg campaign "$campaign" \
                '{severity: $severity, file: $file, package: $package, version: $version, campaign: $campaign}'
        done < "$VERSION_FINDINGS" | jq -s '.' 2>/dev/null || echo "[]")
    fi
    
    local shai_hulud_findings="[]"
    if [ -f "$SHAI_HULUD_FINDINGS" ] && [ -s "$SHAI_HULUD_FINDINGS" ]; then
        shai_hulud_findings=$(while IFS='|' read -r sev file pattern desc campaign; do
            [ -z "$sev" ] && continue
            jq -n \
                --arg severity "$sev" \
                --arg file "$file" \
                --arg pattern "$pattern" \
                --arg description "$desc" \
                --arg campaign "$campaign" \
                '{severity: $severity, file: $file, pattern: $pattern, description: $description, campaign: $campaign}'
        done < "$SHAI_HULUD_FINDINGS" | jq -s '.' 2>/dev/null || echo "[]")
    fi
    
    local workflow_findings="[]"
    if [ -f "$WORKFLOW_FINDINGS" ] && [ -s "$WORKFLOW_FINDINGS" ]; then
        workflow_findings=$(while IFS='|' read -r sev file pattern desc campaign; do
            [ -z "$sev" ] && continue
            jq -n \
                --arg severity "$sev" \
                --arg file "$file" \
                --arg pattern "$pattern" \
                --arg description "$desc" \
                --arg campaign "$campaign" \
                '{severity: $severity, file: $file, pattern: $pattern, description: $description, campaign: $campaign}'
        done < "$WORKFLOW_FINDINGS" | jq -s '.' 2>/dev/null || echo "[]")
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
            while IFS='|' read -r sev file pkg line_num snippet extra; do
                [ -z "$sev" ] && continue
                jq -n \
                    --arg severity "$sev" \
                    --arg file "$file" \
                    --arg package "$pkg" \
                    --arg line "$line_num" \
                    --arg snippet "$snippet" \
                    --arg note "${extra:-}" \
                    '{severity: $severity, file: $file, package: $package, line: $line, snippet: $snippet} + (if $note != "" then {note: $note} else {} end)'
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
        --arg version_match_count "$VERSION_MATCH_COUNT" \
        --arg shai_hulud_count "$SHAI_HULUD_ARTIFACT_COUNT" \
        --arg workflow_count "$WORKFLOW_INJECTION_COUNT" \
        --arg suspicious_scripts "$SUSPICIOUS_SCRIPT_COUNT" \
        --arg credential_theft "$CREDENTIAL_THEFT_COUNT" \
        --arg network_calls "$NETWORK_CALL_COUNT" \
        --arg timing_suspicions "$TIMING_SUSPICION_COUNT" \
        --argjson rdd_findings "$rdd_findings" \
        --argjson malicious_findings "$malicious_findings" \
        --argjson version_findings "$version_findings" \
        --argjson shai_hulud_findings "$shai_hulud_findings" \
        --argjson workflow_findings "$workflow_findings" \
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
            campaigns_detected: (
                (if ($shai_hulud_count | tonumber) > 0 or ($version_match_count | tonumber) > 0 or ($workflow_count | tonumber) > 0 then ["SHAI_HULUD_2"] else [] end) +
                (if ($rdd_count | tonumber) > 0 then ["PHANTOMRAVEN"] else [] end)
            ),
            summary: {
                rdd_count: ($rdd_count | tonumber),
                malicious_packages: ($malicious_count | tonumber),
                compromised_versions: ($version_match_count | tonumber),
                shai_hulud_artifacts: ($shai_hulud_count | tonumber),
                workflow_injections: ($workflow_count | tonumber),
                suspicious_scripts: ($suspicious_scripts | tonumber),
                credential_theft_patterns: ($credential_theft | tonumber),
                suspicious_network_calls: ($network_calls | tonumber),
                timing_suspicions: ($timing_suspicions | tonumber)
            },
            findings: {
                remote_dynamic_dependencies: $rdd_findings,
                malicious_packages: $malicious_findings,
                compromised_versions: $version_findings,
                shai_hulud_artifacts: $shai_hulud_findings,
                workflow_injections: $workflow_findings,
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
    echo "├─ Compromised Versions: $VERSION_MATCH_COUNT"
    echo "├─ Shai-Hulud Artifacts: $SHAI_HULUD_ARTIFACT_COUNT"
    echo "├─ Workflow Injections: $WORKFLOW_INJECTION_COUNT"
    echo "├─ Suspicious Lifecycle Scripts: $SUSPICIOUS_SCRIPT_COUNT"
    
    if [ "$DEEP_SCAN" = true ]; then
        echo "├─ Credential Theft Patterns: $CREDENTIAL_THEFT_COUNT"
        echo "├─ Suspicious Network Calls: $NETWORK_CALL_COUNT"
    fi
    
    if [ "$PARANOID" = true ]; then
        echo "└─ Timing Suspicions: $TIMING_SUSPICION_COUNT"
    fi
    
    echo ""
    
    # Detailed findings - Shai-Hulud 2.0 specific
    if [ -s "$SHAI_HULUD_FINDINGS" ]; then
        echo -e "${RED}${BOLD}🪱 Shai-Hulud 2.0 Artifacts:${NC}"
        echo "════════════════════════════════════════"
        while IFS='|' read -r severity file pattern desc campaign; do
            [ -z "$severity" ] && continue
            echo -e "${RED}[CRITICAL]${NC} $pattern"
            echo "  File: $file"
            echo "  Description: $desc"
            echo ""
        done < "$SHAI_HULUD_FINDINGS"
    fi
    
    if [ -s "$VERSION_FINDINGS" ]; then
        echo -e "${RED}${BOLD}🪱 Compromised Package Versions:${NC}"
        echo "════════════════════════════════════════"
        while IFS='|' read -r severity file pkg version campaign; do
            [ -z "$severity" ] && continue
            echo -e "${RED}[CRITICAL]${NC} $pkg@$version"
            echo "  File: $file"
            echo "  Campaign: $campaign"
            echo ""
        done < "$VERSION_FINDINGS"
    fi
    
    if [ -s "$WORKFLOW_FINDINGS" ]; then
        echo -e "${RED}${BOLD}🪱 GitHub Actions Workflow Issues:${NC}"
        echo "════════════════════════════════════════"
        while IFS='|' read -r severity file pattern desc campaign; do
            [ -z "$severity" ] && continue
            if [ "$severity" = "CRITICAL" ]; then
                echo -e "${RED}[CRITICAL]${NC} $pattern"
            else
                echo -e "${YELLOW}[WARNING]${NC} $pattern"
            fi
            echo "  File: $file"
            echo "  Issue: $desc"
            echo ""
        done < "$WORKFLOW_FINDINGS"
    fi
    
    # Original PhantomRaven findings
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
        while IFS='|' read -r severity file pkg version match_type extra; do
            [ -z "$severity" ] && continue
            echo -e "${RED}[CRITICAL]${NC} $pkg@$version"
            echo "  File: $file"
            echo "  Match Type: $match_type"
            [ -n "$extra" ] && echo "  Namespace: $extra"
            echo ""
        done < "$MALICIOUS_FINDINGS"
    fi
    
    if [ -s "$SUSPICIOUS_SCRIPTS" ]; then
        echo -e "${YELLOW}⚠ Suspicious Lifecycle Scripts:${NC}"
        echo "════════════════════════════════════════"
        head -20 "$SUSPICIOUS_SCRIPTS" | while IFS='|' read -r severity file pkg script content extra; do
            [ -z "$severity" ] && continue
            if [ "$severity" = "CRITICAL" ]; then
                echo -e "${RED}[CRITICAL]${NC} $pkg - $script"
            else
                echo -e "${YELLOW}[WARNING]${NC} $pkg - $script"
            fi
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
    
    local has_shai_hulud=false
    if [ "$VERSION_MATCH_COUNT" -gt 0 ] || [ "$SHAI_HULUD_ARTIFACT_COUNT" -gt 0 ] || [ "$WORKFLOW_INJECTION_COUNT" -gt 0 ]; then
        has_shai_hulud=true
    fi
    
    if [ "$MALICIOUS_PKG_COUNT" -gt 0 ] || \
       [ "$has_shai_hulud" = true ] || \
       ([ "$RDD_COUNT" -gt 0 ] && [ -f "$RDD_FINDINGS" ] && grep -q "CRITICAL" "$RDD_FINDINGS" 2>/dev/null); then
        echo -e "${RED}${BOLD}🚨 CRITICAL: MALWARE DETECTED!${NC}"
        echo ""
        
        if [ "$has_shai_hulud" = true ]; then
            echo -e "${MAGENTA}${BOLD}Campaign Detected: SHAI-HULUD 2.0${NC}"
            echo ""
        fi
        
        echo "IMMEDIATE ACTIONS REQUIRED:"
        echo "1. DO NOT run npm install"
        echo "2. Disconnect this machine from network"
        echo "3. Rotate ALL credentials immediately:"
        echo "   - GitHub tokens: https://github.com/settings/tokens"
        echo "   - npm tokens: npm token list && npm token revoke <id>"
        echo "   - CI/CD secrets (GitHub Actions, GitLab, Jenkins, CircleCI)"
        echo "4. Check ~/.gitconfig and ~/.npmrc for exposure"
        echo "5. Review git audit logs for unauthorized activity"
        
        if [ "$has_shai_hulud" = true ]; then
            echo ""
            echo -e "${MAGENTA}SHAI-HULUD 2.0 SPECIFIC ACTIONS:${NC}"
            echo "6. Check GitHub for self-hosted runners named 'SHA1HULUD'"
            echo "7. Review .github/workflows for discussion.yaml or formatter_*.yml"
            echo "8. Audit GitHub Discussions for suspicious content"
            echo "9. Check for exfiltration to webhook.site"
            echo "10. Review Actions artifacts for secret dumps"
        fi
        
        echo ""
        echo "Consider this machine compromised"
        
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
        echo "Your npm projects appear clean based on known indicators for:"
        echo "  - PhantomRaven (Aug-Oct 2025)"
        echo "  - Shai-Hulud 2.0 (Nov 2025+)"
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
                echo "npm-threat-hunter v${VERSION}"
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
        echo "  ✓ Remote Dynamic Dependencies (PhantomRaven)" >&$target_stream
        echo "  ✓ Known Malicious Packages" >&$target_stream
        echo "  ✓ Compromised Package Versions (Shai-Hulud 2.0)" >&$target_stream
        echo "  ✓ Shai-Hulud Artifact Files" >&$target_stream
        echo "  ✓ GitHub Actions Workflow Injection" >&$target_stream
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
    detect_compromised_versions
    detect_shai_hulud_artifacts
    detect_workflow_injections
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