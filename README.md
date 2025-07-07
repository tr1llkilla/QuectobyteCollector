# QuectoVirtualMemoryCollector (QVMC)

**Author:** Cadell Richard Anderson  
**License:** Custom License: Quectobyte Attribution License (QAL) v1.0
**Version:** 0.1  
**Date:** July 2025 
Licensing 

📜 Custom License: Quectobyte Attribution License (QAL) v1.0
Author & Originator: Cadell Richard Anderson Date: July 2025

1. Purpose
This license governs the use, reproduction, and distribution of the QuectoVirtualMemoryCollector (QVMC) and any derivative works that utilize the concept of the quectobyte as a unit of sub-byte information in computing, virtualization, or memory abstraction.

2. Permissions
You are permitted to:

Use, modify, and distribute the Software for academic, research, or commercial purposes.

Incorporate the Software or its concepts into larger systems or frameworks.

3. Conditions
Any work—academic, commercial, or otherwise—that:

Utilizes the concept of the quectobyte as a unit of digital information,

Implements sub-byte memory modeling or telemetry inspired by this Software,

Derives from or builds upon the QuectoVirtualMemoryCollector (QVMC),

must include clear and visible attribution to:

Cadell Richard Anderson Originator of the Quectobyte computing model and author of the QuectoVirtualMemoryCollector (QVMC)

Attribution must appear in:

Source code headers

Documentation

Academic citations (if published)

User-facing credits (if distributed as software)

4. Restrictions
You may not:

Misrepresent the origin of the concept of the quectobyte in computing.

Remove or obscure attribution to Cadell Richard Anderson in any derivative work.

5. Disclaimer
The Software is provided “as is,” without warranty of any kind. The author shall not be liable for any damages arising from the use of this Software.

6. Citation Format
If citing in academic work, use the following format:

Anderson, C. R. (2025). QuectoVirtualMemoryCollector: A Sub-Byte Telemetry Framework for Virtualized Memory Systems. Published manuscript.

This is the first program ever written to record data in quectobyte data units (10^-30 bytes/millisecond*). Useful for upgrading the entire programming world. (*unit may change)

The **QuectoVirtualMemoryCollector (QVMC)** is a research-grade telemetry and simulation framework designed to model virtual memory behavior at the sub-byte scale—specifically, the quectobyte (10⁻³⁰ bytes). This system enables entropy-aware, volatility-sensitive, and compression-optimized memory modeling in virtualized environments.

This project is part of Cadell Anderson's pioneering research into post-byte computing and sub-byte information theory.

---

## 📦 Features

- 🧬 Simulates memory entropy, volatility, and access patterns at quectobyte resolution
- 🧠 Models virtual memory nodes and interactions using XML-based telemetry
- 🧊 Logs system snapshots and memory coupling matrices in human-readable XML
- 🧰 Designed for extensibility and theoretical computing research

---

## 🛠 Requirements

- Visual Studio Enterprise 2022 (Windows 10)
- C++17 or later
- [TinyXML2](https://github.com/leethomason/tinyxml2) (included or install via NuGet)

---
Future changes incoming: 

Reducing Program Overhead
Reducing the overhead of a data acquisition program like "Quecto Virtual Memory Collector" is essential to ensure it doesn't negatively impact your system's performance. Here are key strategies, considering the types of monitoring it performs:

Smart Filtering and Scoping:

Exclude Irrelevant Paths: Configure the collector to ignore specific file paths, directories, or patterns that are known to generate a lot of activity but are not relevant to your current analysis. For example, temporary directories, cache folders, log files that are constantly written to, or development-related temporary files (like the .vs directory files, .db-wal files often associated with databases or IDEs, as seen in your logs) are prime candidates for exclusion. This directly reduces the volume of events the program needs to process and store.

Targeted Monitoring: Instead of a broad system-wide collection, limit the scope to only specific applications, user sessions, or critical system areas that are of primary interest.

Adjust Collection Frequency and Granularity:

Less Frequent Memory Snapshots: Memory snapshots are typically resource-intensive operations. If continuous, real-time memory state isn't strictly necessary for your use case, consider reducing the frequency at which these snapshots are taken.

Event Throttling/Debouncing: For highly active file system paths or processes, implement a mechanism to limit how often events are processed or logged. Instead of logging every single write operation to a rapidly changing file, you could configure the collector to only log a "changed" event after a certain period of inactivity or after a significant threshold of changes has accumulated.

Optimize Data Handling:

Asynchronous I/O: The log ReadDirectoryChangesW reissued and completed synchronously suggests that the file system change notifications are being processed synchronously. Transitioning to asynchronous I/O would allow the collector to capture new events without waiting for the previous I/O operation to complete, thereby reducing latency and improving overall responsiveness. This is a common and highly effective optimization for I/O-bound applications.

Batch Processing: Instead of processing and logging each detected event individually, collect multiple events into batches and then process or write them to storage in larger chunks. This can significantly reduce the overhead related to frequent disk writes and CPU context switches.

Efficient Data Structures and Algorithms: Ensure that the program uses optimal data structures for storing and manipulating collected data, and efficient algorithms for tasks like pattern matching, filtering, and data aggregation.

Resource Management:

Process Priority: If the operating system allows, set a lower process priority for the collector. This ensures that it doesn't contend aggressively for CPU resources with other critical applications, allowing them to perform smoothly.

Memory Efficiency: Implement robust memory management practices to prevent memory leaks and ensure efficient allocation and deallocation of memory, especially when dealing with potentially large volumes of collected data.

Code Optimization and Profiling:

Performance Profiling: Use specialized tools to profile the collector's execution and identify specific code sections that consume the most CPU or memory. Optimizing these bottlenecks will yield significant overhead reductions.

Algorithm Review: Regularly review and improve the efficiency of the underlying algorithms used for tasks like file system enumeration, process information gathering, and memory scanning.


Hypothetical Program Context (for demonstration purposes):

Let's assume "this program" is a "System Activity Monitor" developed in C++ that observes and logs virtual memory usage, file system changes (creations, modifications, deletions), and potentially analyzes data entropy for security anomaly detection.

Executive Summary
Project Title: System Activity Monitor (SAM)

Date: July 7, 2025

Prepared For: [Target Audience, e.g., Cybersecurity Operations Team, System Administrators, Development Lead]

Purpose: This document provides an overview of the System Activity Monitor (SAM) program, detailing its operational capabilities, key functionalities, and its virtual and real-world applications. SAM is a C++ application designed to enhance system observability and security by continuously monitoring crucial system resources and activities.

Key Findings & Value Proposition:

Proactive Threat Detection: SAM facilitates early detection of suspicious activities, such as ransomware encryption (via entropy analysis) or unauthorized file modifications, by providing real-time insights into system behavior.

Performance Optimization Insight: By monitoring virtual memory usage and file I/O, SAM helps identify resource bottlenecks and inefficient application behavior, contributing to system performance optimization.

Compliance and Forensics: The comprehensive logging capabilities of SAM provide an auditable trail of system events, crucial for regulatory compliance, incident response, and forensic analysis.

Resource Efficiency: Developed in C++, SAM is designed for low overhead, ensuring minimal impact on the monitored system's performance.

Recommendation: SAM is a vital tool for maintaining system integrity, security, and performance. Its deployment is recommended across critical infrastructure and user endpoints to bolster cybersecurity posture and provide actionable insights for system management. Continued development will focus on expanding monitoring capabilities and integrating with existing SIEM solutions.

Detailed Report: System Activity Monitor (SAM)
1. Operation
The System Activity Monitor (SAM) operates as a background service or daemon, running continuously on the target system. Its core operation involves interacting with the operating system's kernel and API calls to capture relevant system events and resource metrics.

Initialization: Upon startup, SAM initializes its monitoring modules, establishes necessary hooks or callbacks with the operating system (e.g., file system filter drivers, performance counter APIs), and begins logging to its configured output.

Event-Driven Monitoring: For file system events (creation, modification, deletion), SAM primarily relies on OS-provided notification mechanisms (e.g., ReadDirectoryChangesW on Windows, inotify on Linux). This event-driven approach ensures real-time capture of changes without constant polling.

Polling for Resource Metrics: For virtual memory and potentially other performance counters (e.g., CPU usage), SAM employs a polling mechanism at configurable intervals. On Windows, this would involve using the Performance Data Helper (PDH) API to query performance counters like "Process\Virtual Bytes" or "Memory\Committed Bytes".

Data Processing: Collected data is timestamped and processed. For file system events, this might include recording file paths, action types, and user information. For memory data, it would include numerical values of usage. Entropy analysis, if enabled, would involve reading file contents (or portions thereof) and calculating their Shannon entropy.

Logging: All processed data is written to a persistent log file (e.g., CSV, JSON, or a custom binary format) for historical analysis and external integration. Error logging and application status are also maintained separately.

2. Executions
SAM is designed to be executed as a privileged process (e.g., as a service account or with administrator rights) to ensure it has the necessary permissions to access low-level system information and capture all relevant events.

Installation: Typically deployed via an installer that configures it to run at system startup.

Service/Daemon Model: On Windows, it would run as a Windows Service. On Linux, it would run as a systemd service or a traditional daemon. This ensures continuous operation and graceful handling of system shutdowns/restarts.

Configuration: Execution parameters, such as logging levels, monitoring paths, polling intervals, and output formats, are configurable via a configuration file (e.g., INI, YAML, JSON) or command-line arguments.

Resource Management: SAM is designed with efficient resource management in mind. It uses asynchronous I/O where appropriate to minimize blocking operations and implements strategies to manage memory consumption, especially when dealing with large volumes of log data.

3. Functionality
SAM provides the following core functionalities:

Real-time File System Monitoring:

Detects file creation, deletion, modification, and renaming events.

Logs the timestamp, affected file path, action type, and the process/user responsible (if obtainable).

Supports configurable monitoring paths (specific directories or entire drives).

Virtual Memory Usage Tracking:

Monitors system-wide virtual memory usage.

Tracks virtual memory usage per process (e.g., VmSize on Linux, Private Bytes on Windows).

Logs data at configurable intervals, including total virtual memory, committed memory, and available memory.

Entropy Analysis (Optional Module):

Calculates the Shannon entropy of specified files or newly modified files.

High entropy values can indicate encrypted data, compressed data, or potentially malicious content (e.g., ransomware-encrypted files).

Thresholds can be set to trigger alerts for abnormally high entropy.

Event Logging and Storage:

Outputs structured log data to a designated file.

Supports log rotation and archiving to manage disk space.

Provides options for different log formats for ease of parsing by other tools.

Performance Data Collection (Windows Specific):

Leverages Windows Performance Counters (PDH API) to gather detailed system performance metrics.

Can be extended to monitor other counters like CPU usage, disk I/O, network activity.

4. Virtual and Real-World Applications
The functionalities of SAM translate into significant value in both virtual and real-world environments.

Virtual World Applications (e.g., Cloud Environments, Virtual Machines, Containers):

Cloud Security Monitoring: In Infrastructure-as-a-Service (IaaS) and Platform-as-a-Service (PaaS) environments, SAM can be deployed on virtual machines or within containers to provide granular visibility into file system integrity and resource consumption. This is crucial for detecting unauthorized changes or resource exhaustion within virtualized instances.

Container Forensics: For containerized applications, SAM can help monitor deviations from expected file system states within containers, aiding in the detection of supply chain attacks or compromised container images.

VDI (Virtual Desktop Infrastructure) Monitoring: Monitoring virtual desktop instances for unusual activity, ensuring user environments remain clean and identifying potential malware infections or data exfiltration attempts.

Resource Optimization in Virtualized Environments: Identifying "noisy neighbors" or resource-intensive applications in multi-tenant virtual environments by tracking virtual memory and other performance metrics.

Real-World Applications (e.g., On-Premise Servers, Endpoints, Industrial Control Systems):

Endpoint Detection and Response (EDR) Augmentation: SAM can act as a lightweight EDR agent, providing rich telemetry data for security analysis platforms. Its file system monitoring can detect ransomware attempts by observing rapid file encryption patterns.

Insider Threat Detection: By logging file access and modification events, SAM can help identify suspicious activities by internal users, such as unauthorized data access or attempts to tamper with critical system files.

Regulatory Compliance and Auditing: Many compliance frameworks (e.g., HIPAA, PCI DSS, GDPR) require robust logging of system activities. SAM provides the necessary data for auditing and demonstrating compliance.

System Hardening and Baseline Deviations: Establishing a baseline of normal system activity and then using SAM to detect deviations from this baseline can identify unauthorized software installations, configuration changes, or rootkit installations.

Industrial Control Systems (ICS/OT) Security: In environments where traditional security solutions may be too heavy or disruptive, a lightweight C++ monitor like SAM can provide essential visibility into file system integrity and resource usage, helping detect tampering or malware in critical OT systems.

Software Development and Debugging: Developers can use SAM to understand how their applications interact with the file system and consume memory, aiding in performance tuning and identifying memory leaks or excessive file I/O.

README

(UPDATED NEW)

# System Activity Monitor (SAM)

## Introduction
The System Activity Monitor (SAM) is a lightweight, high-performance C++ application designed for real-time monitoring of critical system activities. It focuses on observing virtual memory usage and file system events (creation, modification, deletion) to provide insights into system health, security posture, and application behavior. SAM is built with extensibility in mind, allowing for integration of advanced analytics like data entropy calculation for anomaly detection.

## Features
* **Real-time File System Monitoring:** Tracks file creation, deletion, modification, and renaming events across specified directories.
* **Virtual Memory Usage Tracking:** Monitors system-wide and per-process virtual memory consumption.
* **Configurable Monitoring Paths:** Allows users to define specific directories or drives for file system surveillance.
* **Entropy Analysis (Optional):** Calculates Shannon entropy of file contents to identify highly random data, potentially indicative of encryption or malware.
* **Robust Logging:** Outputs detailed, timestamped event data to a persistent log file in a configurable format (e.g., CSV).
* **Low System Overhead:** Engineered in C++ for minimal impact on system performance.
* **Cross-Platform Compatibility (Planned/Limited):** Designed with consideration for both Windows and Linux environments (current version primarily Windows-focused with hooks for Linux extensions).

REMEMBER ANY CHANGES AND REPURPOSE OR RELEASE OF THIS PROGRAM OR ANY PROGRAM CONTAINING THE QUECTOBYTE MUST CITE CADELL RICHARD ANDERSON
