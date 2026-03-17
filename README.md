# EDR Lite – eBPF-Based Behavioral Detection Engine

EDR Lite is a **lightweight Endpoint Detection and Response prototype** for Linux built using eBPF and SQLite. The system collects security-relevant system events directly from the Linux kernel and applies behavioral detection rules to identify suspicious activity.

The goal of this project is **to demonstrate how modern EDR solutions monitor** system activity, correlate events, and detect malicious behavior using low-level telemetry rather than signatures.

This project is intended as an **educational** and **technical demonstration** of kernel telemetry collection and behavioral detection techniques.

---

## Features

- Real-time monitoring of system activity using eBPF
- Kernel-level visibility into process, file, and network operations
- Event normalization and storage in SQLite
- Behavioral detection rules implemented with SQL queries
- Correlation between multiple system events
- Lightweight architecture with minimal dependencies
- Console-based alerting system

---

## Requirements

Linux kernel 5.8 or newer
Clang
LLVM
libbpf
SQLite3
GCC or Clang compiler
Root privileges

**A recent Linux distribution such as Ubuntu, Debian, Fedora, or Arch Linux is recommended.**

---

## Installation

Install the required dependencies.

On Debian or Ubuntu systems install:

clang
llvm
libbpf-dev
libelf-dev
sqlite3
libsqlite3-dev
build-essential
bpftool

Other distributions require equivalent packages.

---

## Build Instructions

**Clone the repository.**

**Enter the project directory.**

**Compile the project.**

make

**This will build:**

the eBPF program
the user space monitoring engine

---

## Running the EDR

The program must be executed with root privileges.

**Run the EDR engine:**

sudo ./edr

The program will start monitoring system activity and printing alerts when suspicious behaviors are detected.

---

## Architecture

The system is composed of **four main components**.

- Kernel telemetry collection using eBPF
- Event ingestion and normalization in user space
- SQLite database used as a behavioral timeline
- Detection engine executing correlation rules

#### High level flow:

Linux Kernel
↓
eBPF programs capture system calls
↓
Events are sent to user space through a ring buffer
↓
Events are normalized and stored in SQLite
↓
Detection rules correlate database's events and generate alerts


#### eBPF Monitoring

The eBPF programs monitor **several security-relevant Linux system calls** including:

- execve
- openat
- read
- write
- connect
- bind
- listen
- accept
- unlink
- rename

These syscalls provide **visibility** into:

- process execution
- file access
- network activity
- persistence attempts
- process relationships

Events collected in the kernel are transferred to user space using a ring buffer.

---

## Event Storage

All events are stored in a **local SQLite database**. The database acts as a timeline of system activity.

Core tables include:
- events
- exec_events
- connect_events
- openat_enter_events
- read_events
- write_events
- bind_events
- listen_events
- accept_events
- renameat2_events

The events table **stores common metadata** such as:

event identifier
timestamp
process identifier
parent process identifier
user identifier
process name

Other tables store event-specific data such as file paths or network addresses.

---

## Detection Engine

The detection engine **periodically runs** a set of **behavioral rules** implemented as **SQL queries**. Each rule correlates multiple events in order to identify **suspicious** patterns.

**Instead of detecting isolated events, the engine detects behaviors such as:**

- execution of files from suspicious locations
- access to sensitive files
- network connections initiated after process execution
- possible persistence mechanisms
- suspicious parent-child process relationships

When a rule is triggered, an alert is printed in the terminal.

**Example alert structure:**

Alert name
timestamp
process id
parent process id
user id
process name
additional context such as file path or destination IP

---

## Detection Rules

The current implementation includes 19 behavioral detection rules covering **execution anomalies, sensitive file access, network activity, and suspicious process behaviors**. These rules correlate low-level system events in order to detect patterns commonly associated with malware execution, credential access, persistence mechanisms, and command-and-control communication.

---

#### Execution Anomalies

**Execution from temporary directories**
Detects processes executed from /tmp, a location commonly used to store temporary or malicious payloads.

**Execution from user home directories**
Detects binaries executed directly from user home directories, which can indicate dropped malware or staged payloads.

**Execution from hidden directories**
Detects execution of binaries from hidden directories (directories starting with a dot), often used to hide malicious files.

**Execution after writing a file to /tmp**
Detects files that are first opened for writing in /tmp and then executed shortly after, a common pattern for dropped payloads.

**Execution of shell processes**
Detects execution of shell interpreters such as bash or sh which may be used to launch further commands or payloads.

---

#### Sensitive File Access

**Read access to /etc/passwd**
Detects processes reading the /etc/passwd file, which may indicate enumeration of local users.

**Read access to /etc/shadow**
Detects access to /etc/shadow, a sensitive file containing password hashes.

**Access to SSH key files**
Detects processes accessing SSH key files which may indicate credential harvesting or lateral movement preparation.

**Modification of ~/.ssh/authorized_keys**
Detects writes to the authorized_keys file, a common persistence technique allowing attackers to maintain SSH access.

**Modification of shell startup files**
Detects writes to .bashrc, which may indicate attempts to establish persistence through shell initialization scripts.

---

#### Network Activity

**Process execution followed by network connection**
Detects processes that initiate a network connection shortly after being executed, which can indicate command-and-control communication.

**Execution from /tmp followed by network activity**
Detects payloads executed from /tmp that subsequently initiate network connections.

**Shell process initiating a network connection**
Detects shell processes that open outbound network connections, often associated with reverse shells.

**Connection to external IP addresses**
Detects outbound connections to external IP addresses outside of the local system.

**Server socket creation** (bind → listen → accept)
Detects processes opening server sockets, which may indicate backdoors or unauthorized services.

---

#### Suspicious Process Behavior

**Execution from /dev/shm**
Detects execution from /dev/shm, a memory-backed filesystem frequently abused for fileless malware or temporary payload staging.

**Execution from /var/tmp**
Detects execution of files stored in /var/tmp, another writable location often abused for persistence or payload staging.

**Execution of common network tools**
Detects execution of tools commonly used for network communication such as curl, wget, nc, or scripting interpreters used for payload retrieval.

**Process execution triggered by network tools**
Detects processes spawned by network utilities, which may indicate payload execution following download or staging activity.

---

#### Example Detection Scenario

Payload execution from a temporary directory:

**Create a payload:**

echo “nc 1.1.1.1 80” > /tmp/payload.sh

**Make it executable:**

chmod +x /tmp/payload.sh

**Execute the payload:**

/tmp/payload.sh

**Possible alerts triggered:**

EXEC_FROM_TMP
EXEC_AFTER_TMP_OPEN_WRITE
EXEC_THEN_CONNECT

---

## Project Goals

**This project demonstrates:**

- how to collect security telemetry using eBPF
- how kernel events can be transformed into a behavioral timeline
- how detection rules can correlate multiple system events
- how modern EDR engines analyze system activity

The objective is to provide a clear technical demonstration of behavioral detection mechanisms on Linux.

---

## Limitations

This project is a prototype and has several limitations.

Limited syscall coverage
No advanced process lineage reconstruction
No distributed telemetry collection
No remote alerting or SIEM integration
No automatic noise filtering or whitelisting

The focus of the project is on demonstrating detection concepts rather than building a production-grade EDR.

---

## Technologies Used

C
eBPF and libbpf
SQLite
Linux kernel tracing
Ring buffer communication

---

## License

This project is released for **educational** and **research** purposes.