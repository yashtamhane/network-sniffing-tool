Network Sniffing Tool
=====================

Description:
------------
This tool (capture.py) is a Python-based network packet sniffer built using Scapy.
It captures live traffic (or reads from a pcap file) and parses HTTP, TLS, and DNS
requests. The tool works irrespective of the destination port, allowing it to
detect “hidden” HTTP/TLS/DNS servers that use non-standard ports. An optional
BPF filter expression (like those used in tcpdump) can be provided to capture only
a subset of the traffic.

Features:
---------
1. HTTP:
   - Parses GET and POST requests.
   - Extracts the HTTP method, destination host (from the "Host:" header), and
     the Request URI.
2. TLS:
   - Parses TLS Client Hello messages.
   - Extracts the SNI (Server Name Indication) hostname.
3. DNS:
   - Parses DNS queries for A-records.
   - Extracts the queried domain name.

Each captured packet is printed with a timestamp and the source/destination
IP addresses and ports.

Usage:
------
Live capture (requires root privileges):
  sudo python3 capture.py -i <interface> [BPF filter expression]
  Example:
    sudo python3 capture.py -i eth0 "host 192.168.0.123"

Read from a pcap file:
  python3 capture.py -r <tracefile> [BPF filter expression]

Testing:
--------
Test scripts are provided in the repository under the tests directory.

1. DNS Test:
   - Directory: tests/dns
   - File: dns_server.py
   - Description: Runs a DNS server on 127.0.0.1:5353 that always responds with
     an A record pointing to 127.0.0.1.
   - Run with:
         python3 tests/dns/dns_server.py

2. HTTP Test:
   - Directory: tests/http
   - Files:
         http_server.py – A simple HTTP server running on port 8080.
         http_client.py – A client that sends a GET request to the HTTP server.
   - Run the server:
         python3 tests/http/http_server.py
     Then, in another terminal, run the client:
         python3 tests/http/http_client.py

3. TLS Test:
   - Directory: tests/tls
   - Files:
         tls_server.py – A TLS server running on port 8443.
         tls_client.py – A TLS client that connects and sends an HTTP GET request.
         cert.pem, key.pem – TLS certificate and key (generate with OpenSSL if needed).
   - Generate certificate (if not already present):
         openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=localhost"
   - Run the server:
         python3 tests/tls/tls_server.py
     Then, in another terminal, run the client:
         python3 tests/tls/tls_client.py

Sample Output:
--------------
Example using the loopback interface:
--------------------------------------------------
$ sudo python3 capture.py -i lo

2025-02-28 20:53:55.148597 HTTP 127.0.0.1:50670 -> 127.0.0.1:8080 localhost:8080 GET /test
2025-02-28 20:53:55.148774 HTTP 127.0.0.1:50670 -> 127.0.0.1:8080 localhost:8080 GET /test
2025-02-28 20:54:28.605606 DNS 127.0.0.1:35072 -> 127.0.0.1:5353 www.example.com
2025-02-28 20:54:28.606676 DNS 127.0.0.1:35072 -> 127.0.0.1:5353 www.example.com
2025-02-28 20:55:14.050267 TLS 127.0.0.1:56120 -> 127.0.0.1:8443 localhost
2025-02-28 20:55:14.050800 TLS 127.0.0.1:56120 -> 127.0.0.1:8443 localhost
--------------------------------------------------

Example capturing live traffic on eth0 (e.g., for amazon.com and aniwatch.com):
--------------------------------------------------
$ sudo python3 capture.py -i eth0

2025-02-28 21:06:18.534492 DNS 192.168.80.130:42822 -> 192.168.80.2:53 ads-img.mozilla.org
2025-02-28 21:06:18.556679 TLS 192.168.80.130:33660 -> 34.36.54.80:443 ads-img.mozilla.org
2025-02-28 21:06:19.613734 DNS 192.168.80.130:50746 -> 192.168.80.2:53 www.amazon.com
2025-02-28 21:06:19.628500 TLS 192.168.80.130:43334 -> 23.202.154.76:443 www.amazon.com
...
2025-02-28 21:06:26.027978 HTTP 192.168.80.130:42048 -> 104.18.38.233:80 ocsp.sectigo.com POST /
--------------------------------------------------

Repository Structure:
---------------------
network/
  ├─ src/
  │    └─ capture.py
  └─ tests/
       ├─ dns/
       │     └─ dns_server.py
       ├─ http/
       │     ├─ http_server.py
       │     └─ http_client.py
       └─ tls/
             ├─ cert.pem
             ├─ key.pem
             ├─ tls_server.py
             └─ tls_client.py
       └─ ReadMe.md

Dependencies:
-------------
- Python 3.x
- Scapy
- dnslib (for DNS test server)
- OpenSSL (for generating TLS certificates)

Notes:
------
- Root privileges may be required for live packet capture.
- The tool does not perform TCP stream reassembly; it parses each packet individually.
- This project is intended for educational purposes and basic network traffic analysis.

