// qvmc_collector.h
#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <fstream>
#include <sstream> // For internal string manipulation
#include <windows.h> // For Win32 APIs
#include <Psapi.h>   // For process memory info (GetProcessMemoryInfo, EnumProcesses)
#include <Pdh.h>     // For Performance Data Helper API (system-wide performance counters)
#include <filesystem> // For std::filesystem::create_directories
#include "tinyxml2.h" // For XML serialization

// Linker directives for required libraries
#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Psapi.lib")

namespace QVMC {

    // Forward declarations for cleaner headers
    struct QVMNode;
    struct QVMEdge;
    struct VirtualMemorySnapshot;

    // --- Data Structures ---

    // Refined QVMNode to capture more relevant memory entity details
    struct QVMNode {
        std::string id;          // Unique ID (e.g., ProcessID, MemoryRegionAddress)
        std::string type;        // "Process", "Module", "MemoryPage", "VirtualAddressSpace"
        std::string name;        // Name for Processes/Modules, or descriptive for MemoryPages
        // Additional metrics for nodes, if applicable (e.g., total committed bytes for a process)
        double current_committed_bytes;
        double peak_committed_bytes;

        std::string toXML() const; // For serializing node details if needed
    };

    struct QVMEdge {
        std::string source_node_id;
        std::string target_node_id;
        std::chrono::system_clock::time_point timestamp;
        std::vector<std::vector<double>> quecto_coupling_matrix; // Multidimensional interaction (e.g., [Read_Rate, Write_Rate, PageFault_Rate])
        std::vector<std::string> context_tags; // e.g., "paging", "access", "process_interaction", "VS_activity"

        std::string toXML() const;
    };

    // Refined VirtualMemorySnapshot to directly map to Pdh and process metrics
    struct VirtualMemorySnapshot {
        std::chrono::system_clock::time_point timestamp;

        // "Plasma" metrics (system-wide memory performance) - from Pdh API
        double system_commit_bytes_total;    // Total committed virtual memory (including page file)
        double system_available_bytes;       // Available physical memory + space in page file
        double system_page_faults_per_sec;   // Rate of hard/soft page faults
        double system_pages_input_per_sec;   // Pages read from disk to satisfy faults
        double system_pages_output_per_sec;  // Pages written to disk (for pagefile)

        // "Entropy Map" (e.g., randomness/unpredictability in memory access patterns)
        // This will be derived from collected access patterns, not directly from API.
        // For now, it's a derived/calculated metric, potentially represented by fractal features.
        std::vector<double> entropy_map_derived; // Placeholder for derived fractal/entropy features

        // "Volatility Map" (e.g., rate of change in memory usage, or churn)
        // Derived from diffs in process memory stats or page fault rates.
        std::vector<double> volatility_map_derived; // Placeholder for derived volatility features

        // "Compression Map" (Windows memory compression)
        double system_compressed_pages_total; // Sum of pages in memory compression store

        // "Access Heatmap" (per-process/per-page access - complex, will be represented as a vector of hotspots)
        // This will represent top N processes by page faults, or memory working set changes.
        std::vector<std::pair<std::string, double>> process_memory_hotspots; // Process name/ID and a metric (e.g., working set size, page faults)

        std::string toXML() const; // Ensure this is consistently declared as const member
    };

    // --- Collector Class ---

    class QuectoVirtualMemoryCollector {
    public:
        // Constructor now explicitly requires a monitored_dir path
        QuectoVirtualMemoryCollector(const std::string& log_dir, const std::string& monitored_dir);
        ~QuectoVirtualMemoryCollector();

        void start_collection();
        void stop_collection();

        void on_qvm_edge_captured(const QVMEdge& edge);
        void on_snapshot_captured(const VirtualMemorySnapshot& snapshot);

    private:
        std::atomic<bool> running_ = false;
        std::thread edge_collector_thread_;
        std::thread snapshot_collector_thread_;
        std::thread file_system_collector_thread_; // New thread for file system monitoring
        std::string monitored_code_directory_;     // Member to store the path to monitor

        std::mutex log_mutex_; // Protects file writing

        std::string log_directory_;
        std::ofstream edge_log_file_;
        std::ofstream snapshot_log_file_;

        // Pdh API handles and counters for system-wide performance
        PDH_HQUERY phQuery_; // Query handle
        PDH_HCOUNTER phTotalCommitBytes_;
        PDH_HCOUNTER phAvailableBytes_;
        PDH_HCOUNTER phPageFaultsPerSec_;
        PDH_HCOUNTER phPagesInputPerSec_;
        PDH_HCOUNTER phPagesOutputPerSec_;
        PDH_HCOUNTER phCompressedPages_; // For memory compression store

        bool InitializePdhCounters();
        void ClosePdhCounters();
        void QueryPdhCounters(VirtualMemorySnapshot& snapshot); // Populates snapshot with system-wide data

        // Loops for data collection
        void edge_collector_loop();
        void snapshot_collector_loop();
        void file_system_collector_loop(); // Private method for file system monitoring loop

        // Helper functions for real data acquisition
        std::vector<std::pair<std::string, double>> get_process_memory_hotspots();

        // XML serialization helpers (already in your .cpp)
    };

} // namespace QVMC