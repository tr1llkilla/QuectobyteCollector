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

This is the first program ever written to record data in quectobyte data units. Useful for upgrading the entire programming world.

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

REMEMBER ANY CHANGES AND REPURPOSE OR RELEASE OF THIS PROGRAM OR ANY PROGRAM CONTAINING THE QUECTOBYTE MUST CITE CADELL RICHARD ANDERSON
