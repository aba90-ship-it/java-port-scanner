# java-port-scanner

A multithreaded TCP port scanner written in Java. It scans a range of ports on a host, reports which are open, and flags commonly exploited services (such as Telnet, FTP, SMB, and RDP) in a short risk summary.

## How it works

- Uses Java sockets to test each port with a 300 ms timeout
- Scans ports concurrently with a thread pool of 100 threads
- Compares open ports against a built-in list of commonly risky services
- Prints a report of open ports and a risk summary

## Usage

```
javac PortScanner.java
java PortScanner <host> <startPort> <endPort>
```

Example:

```
java PortScanner scanme.nmap.org 1 1024
```

## Example result

Scanning `scanme.nmap.org` (ports 1 to 1024) found 2 open ports, 22 (SSH) and 80 (HTTP). Neither matched the list of commonly risky services.

## Ethical use

Only scan hosts you own or have permission to test. `scanme.nmap.org` is provided by the Nmap project for practice scanning.
