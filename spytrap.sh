#!/bin/bash

help() {
    cat << EOF
Spytrap - Minimalistic honeypot and monitoring tool for Linux
https://github.com/LucaReggiannini/spytrap
Usage: spytrap.sh [OPTIONS]

This tool sets up lightweight honeypots (HTTP, DNS, Echo services) and monitors 
specified file accesses or modifications. It is designed to detect and log 
potential intrusions with minimal dependencies and high efficiency.

When a malicious event is detected, spytrap sends a desktop notification to the 
user via "notify-send" and writes the logs under the "\$HOME/.spytrap" folder.
Specific actions:
- when an operation is detected on a canary file, the current processes and network
  connections are dumped using "ps" and "ss".The dump is saved in the directory: 
  "\$HOME/.spytrap/dumps".
- for each incoming connection to the honeypots, information about the remote IP 
  (such as its MAC address and the local interface receiving the connection) is 
  logged. To analyze the content of these connections, enable 
  "--tcpdump-capture" option. This will save a ".pcap" file in the directory: 
  "\$HOME/.spytrap/pcaps".


Options:
  --honeypot-http-port <port>      Start an HTTP honeypot on the specified port.
  --honeypot-dns-port <port>       Start a DNS honeypot on the specified port. 
                                   Requests are proxied to an upstream DNS server.
  --honeypot-dns-remote-host <ip>  Specify the upstream DNS server for DNS honeypot.
                                   Default: 8.8.8.8
  --honeypot-dns-remote-port <port>
                                   Specify the upstream DNS port. Default: 53.
  --honeypot-echo-port <port>      Start an Echo honeypot on the specified port.
  --canary-file <path>             Monitor specified files or directories for 
                                   access, modification, or attribute changes.
                                   Use it multiple times to declare multiple files.
  --tcpdump-capture                Enable packet capture on all honeypot ports 
                                   using tcpdump.
  --help                           Display this help message and exit.

Examples:
  spytrap.sh --honeypot-http-port 8080 --honeypot-dns-port 8053 \\
             --honeypot-echo-port 12345 --canary-file /home/user/important.txt \\
             --tcpdump-capture

  spytrap.sh --honeypot-dns-port 8053 --honeypot-dns-remote-host 1.1.1.1

Disclaimer:
- This code is in an early development stage and has not been thoroughly refined or
  tested. Use it with caution
- Always ensure the tools used by this script (ncat, tcpdump, iproute2...) are up 
  to date to avoid potential vulnerabilities.
- Be cautious when configuring an upstream DNS server using option 
  --honeypot-dns-remote-host. Misuse of this function, or relying on third-party 
  servers, depending on the context, can lead to risks such as exposure to third 
  parties, DNS spoofing, traffic interception, and monitoring of sensitive data.
- Spytrap is not a substitute for a complete security solution. The author of this
  project developed it for educational purposes, tailored to meet specific personal 
  needs.
- Avoid exposing honeypot ports directly to the internet without a firewall or 
  rate-limiting to prevent resource exhaustion (e.g., DDoS).
- Be smart

Why this project:
This project was designed to meet my personal needs and preferences:
- Minimalism: I kept the code as simple and minimal as possible, making it easy to 
  understand, debug, and maintain.
- Pre-installed well-known Tools: I used only the software already present by
  default on my machine, avoiding unnecessary dependencies or setup steps.
- Lightweight Design: The program is designed to run directly on the monitored
  machine with minimal resource usage while remaining effective.
- Adaptability in Untrusted Networks: I specifically designed Spytrap to work on 
  untrusted networks without requiring additional security devices, providing a 
  portable and standalone solution.

EOF
}

get_ip_from_ncat()      { sed -nE 's/.*Ncat: Connection from \[?([0-9a-fA-F:.]+)\]?:[0-9]+\./\1/p'; } # Example: ncat -l -v -p 8080 2>&1 >/dev/null | get_ip_from_ncat
get_mac_from_ip()       { ip --oneline neighbour | sed -nE "s/.*$1 dev (.*?) lladdr ((\w\w:){5}\w\w) .*/\2/p"; }
get_interface_from_ip() { ip --oneline neighbour | sed -nE "s/.*$1 dev (.*?) lladdr ((\w\w:){5}\w\w) .*/\1/p"; }
print_epoch_time()      { date +'%s'; }
print_date()            { date +'%d/%m/%Y %H:%M:%S'; }
print_error()           { echo "[Error] $1" 1>&2; exit 1;}
print_info()            { echo "[Info] $1" 1>&2; }
print_incident()        { echo "[Incident] $1" 1>&2; }
is_valid_port()         { echo "$1" | grep -Pq "^[0-9]+$" && (( "$1" >= 0 && "$1" <= 65535 )) && return 0 || return 1; }
is_valid_ip()           { echo "$1" | grep -Pq "^(\d{1,3}\.){3}\d{1,3}$" && return 0 || return 1; }
check_ports_duplicate() { [[ $(echo "$@" | tr ' ' '\n' | sort | uniq -d | wc -l) -eq 0 ]] || return 1; }
check_ports_busy()      { for port in "$@"; do ss -tuln | grep -q ":$port " && return 1; done; return 0;}


honeypot_http_reply="HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n<!DOCTYPE html><html><head><title>Homepage</title></head><body>Connection: OK<br/>Tunnel: 1<br/>To configure click <a href=\"http://tunnel/login\">here</a></body></html>"
honeypot_http_port=""
honeypot_dns_port=""
honeypot_dns_remote_host="8.8.8.8"
honeypot_dns_remote_port=53
honeypot_echo_port=""
canary_file_paths=()
canary_file_capture_file="$HOME/.spytrap/dumps/$(print_epoch_time).spytrap.txt"
spytrap_capture_file="$HOME/.spytrap/spytrap.log"
tcpdump_capture_file="$HOME/.spytrap/pcaps/$(print_epoch_time).spytrap.pcap"
tcpdump_capture=false
tcpdump_capture_ports=()

mkdir -p "$HOME/.spytrap/pcaps/"
mkdir -p "$HOME/.spytrap/dumps/"

make_log_message() {
	local remote_ip=$2
	local remote_mac=$(get_mac_from_ip "$remote_ip")
	local local_interface=$(get_interface_from_ip "$remote_ip")
	local local_port=$1
	
    local log_message="$(print_date) local_port=$local_port local_interface=$local_interface remote_ip=$remote_ip remote_mac=$remote_mac"
    print_incident "$log_message" 2>> "$spytrap_capture_file"
    print_incident "$log_message"
    notify-send "[Spytrap] [Incident] $remote_ip on port $local_port."
}

honeypot_http() {
    while true; do
        local remote_ip=$(echo -e "$honeypot_http_reply" | ncat -i 1 -lvp "$honeypot_http_port" 2>&1 >/dev/null | get_ip_from_ncat)
        [[ -n "$remote_ip" ]] && make_log_message $honeypot_http_port $remote_ip
    done
}

honeypot_dns() {
    while true; do
        local remote_ip=$(ncat -i 1 -lvup "$honeypot_dns_port" -c "ncat -i 1 -u $honeypot_dns_remote_host $honeypot_dns_remote_port" 2>&1 >/dev/null | get_ip_from_ncat)
        [[ -n "$remote_ip" ]] && make_log_message $honeypot_dns_port $remote_ip
    done
}

honeypot_echo() {
    while true; do
        local remote_ip=$(ncat -i 1 -lvp "$honeypot_echo_port" -c "cat" 2>&1 >/dev/null | get_ip_from_ncat)
        [[ -n "$remote_ip" ]] && make_log_message $honeypot_echo_port $remote_ip
    done
}

canary_file() {
	local command
    command=$(printf "%s " "${canary_file_paths[@]}")
	command="inotifywait -q -m -r -e access,modify,attrib,open --format '%T file=%w operation=%e parent=%f' --timefmt '[Incident] %d/%m/%Y %H:%M:%S' ${command} "
	print_info "Starting file capture: $command"
	bash -c "$command" | while read event; do
		notify-send "[Spytrap] [Incident] Operation on canary file."
    	echo "$event"| tee -a "$spytrap_capture_file"
    	echo -e "\n##############################\n" >> $canary_file_capture_file
    	ps -eF >> $canary_file_capture_file
    	echo "" >> $canary_file_capture_file
    	ss -tupan >> $canary_file_capture_file
    	echo "" >> $canary_file_capture_file
	done
}

tcpdump_capture() {
    local command
    command=$(printf "port %s or " "${tcpdump_capture_ports[@]}")
    command=${command% or }
    command="tcpdump -U -i any -Q in -w ${tcpdump_capture_file} '${command}' 2>/dev/null"
    print_info "Starting network capture: $command"
    bash -c "$command"
}

########
# Main #
########

# Check dependencies
# Very basic commands are not tested (like commands from coreutils)
command -v ncat 1>/dev/null || print_error 'Command "ncat" from package "nmap" not found.'
command -v tcpdump 1>/dev/null || print_error 'Command "tcpdump" from package "tcpdump" not found.'
command -v ss 1>/dev/null || print_error 'Command "ss" from package "iproute2" not found.'
command -v ip 1>/dev/null || print_error 'Command "ip" from package "iproute2" not found.'
command -v ps 1>/dev/null || print_error 'Command "ps" from package "procps-ng" not found.'
command -v sed 1>/dev/null || print_error 'Command "sed" from package "sed" not found.'
command -v grep 1>/dev/null || print_error 'Command "grep" from package "grep" not found.'
command -v notify-send 1>/dev/null || print_error 'Command "notify-send" from package "libnotify" not found.'
command -v inotifywait 1>/dev/null || print_error 'Command "inotifywait" from package "inotify-tools" not found.'

# Parse CLI Arguments
[[ "$#" -eq 0 ]] && help && exit 0
while [[ "$#" -gt 0 ]]; do
    case "$1" in
		--canary-file) canary_file_paths+=("$2"); shift;;
        --honeypot-http-port) honeypot_http_port="$2"; tcpdump_capture_ports+=("$2"); shift;;
        --honeypot-dns-port) honeypot_dns_port="$2"; tcpdump_capture_ports+=("$2"); shift;;
        --honeypot-dns-remote-host) honeypot_dns_remote_host="$2"; shift;;
        --honeypot-dns-remote-port) honeypot_dns_remote_port="$2"; shift;;
        --honeypot-echo-port) honeypot_echo_port="$2"; tcpdump_capture_ports+=("$2"); shift;;
        --tcpdump-capture) tcpdump_capture=true;;
        --help) help; exit 1;;
        *) print_error "Unknown argument: $1. Use --help for the manual"; exit 1;;
    esac
    shift
done

# Check if arguments are valid
[[ -n "$honeypot_dns_port" ]] && ! is_valid_port "$honeypot_dns_port" && print_error "--honeypot_dns_port: invalid port number."
[[ -n "$honeypot_http_port" ]] && ! is_valid_port "$honeypot_http_port" && print_error "--honeypot_http_port: invalid port number."
[[ -n "$honeypot_echo_port" ]] && ! is_valid_port "$honeypot_echo_port" && print_error "--honeypot_echo_port: invalid port number."
[[ -n "$honeypot_dns_remote_port" ]] && ! is_valid_port "$honeypot_dns_remote_port" && print_error "--honeypot_dns_remote_port: invalid port number."
[[ -n "$honeypot_dns_remote_host" ]] && ! is_valid_ip "$honeypot_dns_remote_host" && print_error "--honeypot-dns-remote-host: invalid IPv4."
check_ports_duplicate "$honeypot_dns_port" "$honeypot_http_port" "$honeypot_echo_port" || print_error "Ports are duplicated"
check_ports_busy "$honeypot_dns_port" "$honeypot_http_port" "$honeypot_echo_port" || print_error "Ports busy"

# Start components
[[ ${#canary_file_paths[@]} -gt 0 ]] && canary_file &
[[ ${#tcpdump_capture_ports[@]} -gt 0 ]] && $tcpdump_capture && tcpdump_capture &
[[ -n "$honeypot_dns_port" ]] && print_info "Starting DNS Honeypot on port $honeypot_dns_port..." && honeypot_dns &
[[ -n "$honeypot_http_port" ]] && print_info "Starting HTTP Honeypot on port $honeypot_http_port..." && honeypot_http &
[[ -n "$honeypot_echo_port" ]] && print_info "Starting HTTP Honeypot on port $honeypot_echo_port..." && honeypot_echo &

#####################
# Cleanup functions #
#####################

tcpdump_capture_clean_file() {
	local f="${tcpdump_capture_file}"
	[[ -f "$f" ]] || return 0
	local fsize=$(du -sb "$f"  | cut -f 1)
	(("$fsize"<=24)) && print_info "Found empty pcap file $f. Cleaning..." && rm -rf "$f" 2>/dev/null
}

get_process_tree() {
  local children=$(ps -o pid= --ppid "$1")
  for pid in $children; do print_info "Sub-process process found: $pid"; get_process_tree "$pid"; done
  echo "$children"
}

cleanup() { 
	print_info "Process interrupted by the user (CTRL-C). Exit..."
	notify-send "[Spytrap] [Info] Shutting down..."
	print_info "Cleaning TcpDump files..."
	[[ ${#tcpdump_capture_ports[@]} -gt 0 ]] && tcpdump_capture_clean_file
	print_info "Stopping all sub-processes (PID $$)..."
	kill -TERM $(get_process_tree $$) 2>/dev/null
	print_info "Stopping..."
	kill 0
	exit 0
}

trap cleanup SIGINT
wait
notify-send "[Spytrap] [Info] Shutdown."
exit 0



