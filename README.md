# spytrap

Minimalistic honeypot and monitoring tool for Linux.

How to use:
```
git clone https://github.com/LucaReggiannini/spytrap
cd spytrap && chmod +x ./spytrap.sh
./spytrap.sh --help
```

Dependencies:

- `nmap` (for `ncat` command)
- `tcpdump`
- `iproute2` (for `ss` and `ip` commands)
- `procps-ng` (for `ps` command)
- `sed`
- `grep`
- `libnotify` (for `notify-send` command)
- `coreutils`

This tool uses `tcpdump`. To execute without `sudo` run:
```
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
```

## Manual

```
Spytrap, version 1.0 - Minimalistic honeypot and monitoring tool for Linux
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
```

## Demo

Below is a simulation of an attacker scanning the network, enumerating services, and performing an RCE on the machine.

In this demo, you can see how Spytrap informs the user about the malicious activity:

![demo GIF](demo.gif)

## Disclaimer
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

## Why this project
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
