#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VT_API_KEY="YOUR_API_KEY_HERE"
OUTPUT_DIR="recon_results"
VERBOSE=false
MAX_PARALLEL_JOBS=20
TIMEOUT=5
MAX_RETRIES=3
CONCURRENT_DOWNLOADS=50

# File patterns (optimized regex)
FILE_PATTERN='\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|apk|msi|dmg)$'

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
█▀█ █▀▀ █▀▀ █▀█ █▄░█ █▀▀ ▀▄▀
█▀▄ ██▄ █▄▄ █▄█ █░▀█ ██▄ █░█ 
         - Achul-N-Dgeng -                                   
              @2025                            
                                  v2.1
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

# Check requirements
check_requirements() {
    local missing_tools=()
    
    for tool in curl wget jq subfinder amass parallel aria2c; do
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

# Optimized Wayback Machine data collection
fetch_wayback() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}"
    
    print_status "Fetching Wayback Machine data for ${domain}"
    
    {
        curl -s --retry $MAX_RETRIES --retry-delay 2 "https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey" > "${output_dir}/endpoints/wayback_urls_1.txt" &
        
        curl -s --retry $MAX_RETRIES --retry-delay 2 "http://index.commoncrawl.org/CC-MAIN-latest-index?url=*.${domain}/*&output=json" | \
            jq -r 'select(.url != null) | .url' 2>/dev/null > "${output_dir}/endpoints/wayback_urls_2.txt" &
        wait
    }

    if [ -f "${output_dir}/endpoints/wayback_urls_1.txt" ] && [ -f "${output_dir}/endpoints/wayback_urls_2.txt" ]; then
        cat "${output_dir}/endpoints/wayback_urls_"*.txt | sort -u > "${output_dir}/endpoints/wayback_urls.txt"
        rm "${output_dir}/endpoints/wayback_urls_"*.txt
        
        local count=$(wc -l < "${output_dir}/endpoints/wayback_urls.txt")
        print_status "Found ${count} unique URLs from archives"
    else
        print_warning "No archive data found"
        touch "${output_dir}/endpoints/wayback_urls.txt"
    fi
}

# Optimized VirusTotal data collection
fetch_virustotal() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}"
    
    if [ -z "$VT_API_KEY" ] || [ "$VT_API_KEY" = "YOUR_VIRUSTOTAL_API_KEY" ]; then
        print_warning "VirusTotal API key not configured. Skipping VirusTotal data collection."
        return
    fi
    
    print_status "Fetching VirusTotal data for ${domain}"
    
    curl -s --retry $MAX_RETRIES -H "x-apikey: ${VT_API_KEY}" \
        "https://www.virustotal.com/api/v3/domains/${domain}" 2>/dev/null > "${output_dir}/endpoints/virustotal.json"
    
    if [ -f "${output_dir}/endpoints/virustotal.json" ]; then
        jq -r '.data.attributes.subdomains[]? // empty' "${output_dir}/endpoints/virustotal.json" 2>/dev/null > \
            "${output_dir}/subdomains/vt_subdomains.txt"
    fi
}

# Optimized subdomain enumeration
fetch_subdomains() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}/subdomains"
    local temp_dir="${output_dir}/temp"
    mkdir -p "$temp_dir"
    
    print_status "Starting subdomain enumeration"
    
    {
        # Subfinder
        if command -v subfinder &> /dev/null; then
            debug_log "Running subfinder"
            subfinder -d "$domain" -t 100 -silent 2>/dev/null > "${temp_dir}/subfinder.txt" &
        fi
        
        # crt.sh
        debug_log "Querying crt.sh"
        curl -s --retry $MAX_RETRIES "https://crt.sh/?q=${domain}&output=json" 2>/dev/null | \
            jq -r 'if type == "array" then .[].name_value else empty end' 2>/dev/null > "${temp_dir}/crtsh.txt" &
            
        wait
    }
    
    # Combine results with error checking
    if [ -d "$temp_dir" ]; then
        find "$temp_dir" -type f -name "*.txt" -exec cat {} \; 2>/dev/null | \
            grep -v '^$' | sort -u > "${output_dir}/all_subdomains.txt"
        
        rm -rf "$temp_dir"
        
        local count=$(wc -l < "${output_dir}/all_subdomains.txt" 2>/dev/null || echo "0")
        print_status "Found ${count} unique subdomains"
    else
        print_warning "No subdomain results directory found"
        touch "${output_dir}/all_subdomains.txt"
    fi
}

# Optimized JavaScript analysis
fetch_js_files() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}"
    local js_dir="${output_dir}/js"
    local temp_dir="${js_dir}/temp"
    mkdir -p "$temp_dir"
    
    print_status "Analyzing JavaScript files"
    
    # Extract JS URLs efficiently
    grep -E '\.js$' "${output_dir}/endpoints/wayback_urls.txt" 2>/dev/null | sort -u > "${js_dir}/js_files.txt"
    
    if [ -s "${js_dir}/js_files.txt" ]; then
        # Create aria2c input file
        awk -v dir="$temp_dir" '{print $0 "\n  dir=" dir "\n  out=" NR ".js"}' "${js_dir}/js_files.txt" > "${temp_dir}/aria2c_input.txt"
        
        # Download JS files in parallel using aria2c
        aria2c -i "${temp_dir}/aria2c_input.txt" -j $CONCURRENT_DOWNLOADS -x16 -s16 --quiet=true
        
        # Process JS files in parallel
        find "$temp_dir" -name "*.js" -type f | parallel -j $MAX_PARALLEL_JOBS \
            "grep -hoP '(?<=\")(\/[^\"]+)(?=\")' {} >> ${js_dir}/endpoints.txt 2>/dev/null"
        
        if [ -f "${js_dir}/endpoints.txt" ]; then
            sort -u "${js_dir}/endpoints.txt" -o "${js_dir}/endpoints.txt"
            local count=$(wc -l < "${js_dir}/endpoints.txt")
            print_status "Found ${count} unique endpoints in JavaScript files"
        fi
    else
        print_warning "No JavaScript files found"
        touch "${js_dir}/endpoints.txt"
    fi
    
    rm -rf "$temp_dir"
}

# Optimized parameter extraction
extract_params() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}"
    
    print_status "Extracting URL parameters"
    
    if [ -f "${output_dir}/endpoints/wayback_urls.txt" ]; then
        grep -aoP '(?<=[\?&])[^=&]+(?=\=)' "${output_dir}/endpoints/wayback_urls.txt" 2>/dev/null | \
            sort -u > "${output_dir}/params/parameters.txt"
        
        local count=$(wc -l < "${output_dir}/params/parameters.txt")
        print_status "Found ${count} unique parameters"
    else
        print_warning "No URLs file found for parameter extraction"
        touch "${output_dir}/params/parameters.txt"
    fi
}

# Optimized file search
find_interesting_files() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}"
    
    print_status "Searching for interesting files"
    
    if [ -f "${output_dir}/endpoints/wayback_urls.txt" ]; then
        grep -E "$FILE_PATTERN" "${output_dir}/endpoints/wayback_urls.txt" > \
            "${output_dir}/files/interesting_files.txt"
        
        local count=$(wc -l < "${output_dir}/files/interesting_files.txt")
        print_status "Found ${count} interesting files"
    else
        print_warning "No URLs file found for file search"
        touch "${output_dir}/files/interesting_files.txt"
    fi
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
    mkdir -p "${output_dir}"/{endpoints,files,subdomains,params,js}
    
    # Run initial tasks in parallel
    {
        fetch_wayback "$domain" &
        fetch_virustotal "$domain" &
        fetch_subdomains "$domain" &
        wait
    }
    
    # Run sequential tasks that depend on wayback data
    extract_params "$domain"
    find_interesting_files "$domain"
    fetch_js_files "$domain"
    
    print_status "Reconnaissance completed!"
    print_status "Results stored in: ${output_dir}"
}

main "$@"
