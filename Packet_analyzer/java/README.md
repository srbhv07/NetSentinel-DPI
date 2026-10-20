# NetSentinel-DPI

NetSentinel-DPI is a dependency-free Java packet analyzer and DPI engine. It supports classic PCAP files, Ethernet with IPv4/IPv6, TCP/UDP parsing, TLS ClientHello SNI and HTTP Host extraction, application/domain rules, and a multithreaded load-balancer/fast-path pipeline.

## Build

Requires JDK 11 or newer and PowerShell:

    .\build.ps1

The executable jar is created at build\netsentinel-dpi.jar.

## Inspect packets

    .\run.ps1 analyze ..\test_dpi.pcap
    .\run.ps1 analyze ..\test_dpi.pcap 10

The packet limit may be omitted or set to 0 to read the full capture.

## Filter a capture with DPI rules

    .\run.ps1 dpi ..\test_dpi.pcap ..\filtered.pcap --block-app YouTube
    .\run.ps1 dpi ..\test_dpi.pcap ..\filtered.pcap --block-ip 192.168.1.50 --block-domain '*.tiktok.com'
    .\run.ps1 dpi ..\test_dpi.pcap ..\filtered.pcap --rules ..\blocking_rules.txt --lbs 2 --fps 2

Available options:

- --block-ip <ip> blocks traffic with that source address.
- --block-app <name> blocks a recognized application.
- --block-domain <text> matches a domain substring. A *.example.com rule matches the base domain and its subdomains.
- --block-port <port> blocks traffic with that destination port.
- --rules <file> loads [BLOCKED_IPS], [BLOCKED_APPS], [BLOCKED_DOMAINS], and [BLOCKED_PORTS] sections.
- --lbs <n> and --fps <n> set the number of load-balancer threads and fast-path workers per load balancer.
- --queue-size <n> sets the bounded capacity of each pipeline queue.
- --verbose prints packet actions and worker counts.

The output PCAP keeps the input capture's byte order, timestamp precision, link type, and global header values. Packets that cannot be inspected are forwarded unless a matching source-IP rule applies.
