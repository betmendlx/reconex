#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VT_API_KEY="YOUR_VIRUS_TOTAL_API_KEY_HERE"
OUTPUT_DIR="recon_results"
VERBOSE=false
MAX_PARALLEL_JOBS=10
TIMEOUT=10

# File patterns from first script (more comprehensive)
FILE_PATTERN='\.(?:xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|apk|msi|dmg|tmp|crt|pem|key|pub|asc|git|svn|htaccess|env|webpack|eslint|babel|docker|composer|gradle|mvn|nuget|pip|npm|yarn|ruby|python|php|jsp|asp|aspx|cfm|config|conf|properties|settings|inc|bak~|old|orig|copy|temp|tmp|swp|dump|sql\.gz|wordpress|joomla|drupal|magento|laravel|symfony|react|angular|vue|node_modules)'

# Spinner function for visual feedback
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Debug logging
debug_log() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}[DEBUG] $1${NC}"
    fi
}

print_banner() {
    echo -e "${GREEN}"
    cat << "EOF"


▗▄▄▖ ▗▞▀▚▖▗▞▀▘▄▀▀▚▖▄▄▄▄  ▄▄▄▄ ▗▖  ▗▖
▐▌ ▐▌▐▛▀▀▘▝▚▄▖█  ▐▌█   █    █  ▝▚▞▘ 
▐▛▀▚▖▝▚▄▄▖    █  ▐▌█   █ ▀▀▀█   ▐▌  
▐▌ ▐▌         ▀▄▄▞▘      ▄▄▄█ ▗▞▘▝▚▖
                                    
        - Achul-N-Dgeng -                                   
             @2025                       

                           v2.0
EOF
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_error() {
    echo -e "${RED}[-] Error: $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] Warning: $1${NC}"
}

# Rate limiting function
ratelimit() {
    sleep 2
}

# Check requirements
check_requirements() {
    local missing_tools=()
    
    for tool in curl wget jq subfinder amass parallel; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_warning "Missing tools: ${missing_tools[*]}"
        print_warning "Install with: sudo apt install ${missing_tools[*]}"
        exit 1
    fi
}

# Wayback Machine data collection
fetch_wayback() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}"
    
    print_status "Fetching Wayback Machine data for ${domain}"
    
    curl -s --retry 3 --retry-delay 5 -G "https://web.archive.org/cdx/search/cdx" \
        --data-urlencode "url=*.${domain}/*" \
        --data-urlencode "collapse=urlkey" \
        --data-urlencode "output=text" \
        --data-urlencode "fl=original" > "${output_dir}/endpoints/wayback_urls.txt"

    curl -s "http://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey" >> "${output_dir}/endpoints/wayback_urls.txt"
    
    sort -u "${output_dir}/endpoints/wayback_urls.txt" -o "${output_dir}/endpoints/wayback_urls.txt"
    
    print_status "Found $(wc -l < "${output_dir}/endpoints/wayback_urls.txt") URLs from Wayback Machine"
    ratelimit
}

# VirusTotal data collection
fetch_virustotal() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}"
    
    print_status "Fetching VirusTotal data for ${domain}"
    
    if [ -z "$VT_API_KEY" ] || [ "$VT_API_KEY" = "YOUR_VIRUSTOTAL_API_KEY" ]; then
        print_warning "VirusTotal API key not configured. Skipping VirusTotal data collection."
        return
    fi
    
    curl -s --retry 3 -H "x-apikey: ${VT_API_KEY}" \
        "https://www.virustotal.com/api/v3/domains/${domain}" > "${output_dir}/endpoints/virustotal.json"
    
    jq -r '.data.attributes.subdomains[]? // empty' "${output_dir}/endpoints/virustotal.json" >> "${output_dir}/subdomains/vt_subdomains.txt"
    
    print_status "Saved VirusTotal data"
    ratelimit
}

# Subdomain enumeration
fetch_subdomains() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}/subdomains"
    local temp_dir="${output_dir}/temp"
    mkdir -p "$temp_dir"
    
    print_status "Starting subdomain enumeration"
    
    if command -v subfinder &> /dev/null; then
        debug_log "Running subfinder"
        subfinder -d "$domain" -silent > "${temp_dir}/subfinder.txt" &
        spinner $!
    fi
    
    if command -v amass &> /dev/null; then
        debug_log "Running amass"
        amass enum -passive -d "$domain" > "${temp_dir}/amass.txt" &
        spinner $!
    fi
    
    debug_log "Querying crt.sh"
    curl -s "https://crt.sh/?q=%25.${domain}&output=json" | jq -r '.[].name_value' > "${temp_dir}/crtsh.txt"
    
    cat "${temp_dir}"/*.txt "${output_dir}/vt_subdomains.txt" 2>/dev/null | sort -u > "${output_dir}/all_subdomains.txt"
    rm -rf "$temp_dir"
    
    print_status "Found $(wc -l < "${output_dir}/all_subdomains.txt") unique subdomains"
}

# JavaScript file analysis
fetch_js_files() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}"
    local js_dir="${output_dir}/js"
    local temp_dir="${js_dir}/temp"
    mkdir -p "$temp_dir"
    
    print_status "Analyzing JavaScript files"
    
    grep -E '\.js$' "${output_dir}/endpoints/wayback_urls.txt" > "${js_dir}/js_files.txt"
    
    cat "${js_dir}/js_files.txt" | parallel --bar -j "$MAX_PARALLEL_JOBS" \
        "wget -q -T $TIMEOUT -O ${temp_dir}/{#}.js {} && \
        grep -hoP '(?<=\")(\/[^\"]+)(?=\")' ${temp_dir}/{#}.js >> ${js_dir}/endpoints.txt 2>/dev/null"
    
    sort -u "${js_dir}/endpoints.txt" -o "${js_dir}/endpoints.txt"
    rm -rf "$temp_dir"
    
    debug_log "Analyzed $(wc -l < "${js_dir}/js_files.txt") JavaScript files"
}

# Extract parameters
extract_params() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}"
    
    print_status "Extracting URL parameters"
    grep -oP '(?<=\?|\&)[^=]+(?=\=)' "${output_dir}/endpoints/wayback_urls.txt" | \
        sort -u > "${output_dir}/params/parameters.txt"
    
    print_status "Found $(wc -l < "${output_dir}/params/parameters.txt") unique parameters"
}

# Find interesting files
find_interesting_files() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}"
    
    print_status "Searching for interesting files"
    grep -P "$FILE_PATTERN" "${output_dir}/endpoints/wayback_urls.txt" > \
        "${output_dir}/files/interesting_files.txt"
    
    print_status "Found $(wc -l < "${output_dir}/files/interesting_files.txt") interesting files"
}

# Generate summary
generate_detailed_summary() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}"
    local summary_file="${output_dir}/summary.txt"
    
    print_status "Generating summary report"
    
    {
        echo "Reconnaissance Summary for ${domain}"
        echo "Generated on $(date)"
        echo "=========================================="
        echo
        echo "1. Data Collection Statistics"
        echo "----------------------------------------"
        echo "Total URLs discovered: $(wc -l < "${output_dir}/endpoints/wayback_urls.txt")"
        echo "Total subdomains found: $(wc -l < "${output_dir}/subdomains/all_subdomains.txt")"
        echo "Unique parameters discovered: $(wc -l < "${output_dir}/params/parameters.txt")"
        echo "JavaScript files found: $(wc -l < "${output_dir}/js/js_files.txt")"
        echo "JavaScript endpoints: $(wc -l < "${output_dir}/js/endpoints.txt" 2>/dev/null || echo "0")"
        echo
        echo "2. Interesting Files By Category"
        echo "----------------------------------------"
        echo "Documents:"
        echo "- PDF files: $(grep -c '\.pdf' "${output_dir}/files/interesting_files.txt")"
        echo "- Office files: $(grep -c '\.(doc|docx|xls|xlsx|ppt|pptx)' "${output_dir}/files/interesting_files.txt")"
        echo
        echo "Configuration:"
        echo "- Config files: $(grep -c '\.(conf|config|cfg|ini|env|yml|yaml)' "${output_dir}/files/interesting_files.txt")"
        echo "- Database files: $(grep -c '\.(sql|db|sqlite)' "${output_dir}/files/interesting_files.txt")"
        echo
        echo "Backups:"
        echo "- Backup files: $(grep -c '\.(bak|backup|old|orig|copy|tmp)' "${output_dir}/files/interesting_files.txt")"
        echo "- Archive files: $(grep -c '\.(zip|tar\.gz|rar|7z)' "${output_dir}/files/interesting_files.txt")"
        echo
        echo "3. High-Value Parameters"
        echo "----------------------------------------"
        echo "Authentication related: $(grep -c -i 'auth\|token\|jwt\|key\|api\|secret' "${output_dir}/params/parameters.txt")"
        echo "File operations: $(grep -c -i 'file\|path\|document\|upload' "${output_dir}/params/parameters.txt")"
        echo "Database operations: $(grep -c -i 'id\|select\|query\|where\|sql' "${output_dir}/params/parameters.txt")"
    } > "$summary_file"
    
    print_status "Summary report generated at ${summary_file}"
}

# Main function
main() {
    local OPTIND opt domain
    
    while getopts "vhd:" opt; do
        case ${opt} in
            v )
                VERBOSE=true
                ;;
            h )
                echo "Usage: $0 [-v] [-h] -d domain"
                echo "  -v: Verbose mode"
                echo "  -h: Show this help"
                echo "  -d: Domain to scan"
                exit 0
                ;;
            d )
                domain=$OPTARG
                ;;
            \? )
                echo "Invalid option: -$OPTARG" 1>&2
                exit 1
                ;;
        esac
    done
    
    if [ -z "$domain" ]; then
        echo "Error: Domain is required. Use -d option."
        exit 1
    fi
    
    print_banner
    check_requirements
    
    local output_dir="${OUTPUT_DIR}/${domain}"
    mkdir -p "${output_dir}"/{endpoints,files,subdomains,params,js,certificates,archives}
    
    debug_log "Starting reconnaissance for ${domain}"
    
    fetch_wayback "$domain"
    fetch_virustotal "$domain"
    fetch_subdomains "$domain"
    extract_params "$domain"
    find_interesting_files "$domain"
    fetch_js_files "$domain"
    generate_detailed_summary "$domain"
    
    echo -e "\n${GREEN}[+] Reconnaissance completed!${NC}"
    echo -e "Results stored in: ${output_dir}"
    echo -e "Summary report: ${output_dir}/summary.txt"
}

main "$@"
