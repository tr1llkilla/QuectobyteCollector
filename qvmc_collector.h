# QuectoVirtualMemoryCollector (QVMC)

**Author:** Cadell Richard Anderson  
**License:** Custom License: Quectobyte Attribution License (QAL) v1.0
**Version:** 0.1  
**Date:** July 2025

// qvmc_collector.h
#pragma once

#define NOMINMAX // Prevents issues with min/max macros in Windows.h

// Include Windows.h and Pdh.h directly here to get proper type definitions
// This resolves redefinition errors for HQUERY, HCOUNTER, etc.
#include <windows.h>
#include <Pdh.h>   // For PDH_HQUERY, PDH_HCOUNTER types
#include <Psapi.h> // For PROCESS_MEMORY_COUNTERS, EnumProcesses, GetProcessMemoryInfo, etc.

#include <string>
#include <vector>
#include <chrono>
#include <map>
#include <thread>
#include <mutex>
#include <fstream>
#include <utility> // For std::pair
#include <atomic>  // For std::atomic<bool>
#include <filesystem> // For std::filesystem::recursive_directory_iterator

namespace QVMC {

    // --- Base-e derived constants and small utility ---
    const double E = 2.71828182845904523536; // Euler's number

    // --- Data Structures for Quecto Virtual Memory Model ---

    struct QVMNode {
        std::string id;
        std::string type; // e.g., "Process", "File", "MemoryRegion"
        std::string name; // e.g., process name, file path, memory address range
        double current_committed_bytes = 0.0;
        double peak_committed_bytes = 0.0;

        std::string toXML() const;
    };

    struct QVMEdge {
        std::chrono::system_clock::time_point timestamp;
        std::string source_node_id;
        std::string target_node_id;
        // Transcendental Coupling Metrics (TCM)
        // E.g., [info_volatility_index, contextual_entropy_change, oisac_quality_factor]
        std::vector<double> transcendental_coupling_metrics; // 1D vector

        std::vector<std::string> context_tags; // e.g., "process_lifecycle", "file_edit", "network_activity"

        std::string toXML() const;
    };

    struct VirtualMemorySnapshot {
        std::chrono::system_clock::time_point timestamp;
        // System-wide metrics
        double system_commit_bytes_total = 0.0;
        double system_available_bytes = 0.0;
        double system_page_faults_per_sec = 0.0;
        double system_pages_input_per_sec = 0.0;
        double system_pages_output_per_sec = 0.0;
        double system_compressed_pages_total = 0.0;

        // Derived maps, now potentially more complex with e-based insights
        std::vector<double> entropy_map_derived;    // e.g., regional memory entropy
        std::vector<double> volatility_map_derived; // e.g., regional memory change rate (e-based decay)

        // Process-specific memory hot-spots
        std::vector<std::pair<std::string, double>> process_memory_hotspots; // Process name, WorkingSetSize

        std::string toXML() const;
    };

    // --- TranscendentalInformationLayer (TIL) Class ---
    class TranscendentalInformationLayer {
    public:
        static double calculate_shannon_entropy_ln(const std::vector<double>& probabilities);
        static double calculate_kl_divergence(const std::vector<double>& p, const std::vector<double>& q);
        static double calculate_e_factor_change(double initial_value, double change_rate, double time_delta);

        static std::vector<double> derive_transcendental_coupling_metrics(
            const std::vector<std::string>& context_tags,
            double vm_change_magnitude,   // e.g., change in committed bytes
            double file_change_magnitude, // e.g., size change of a monitored file
            double file_entropy          // entropy of a monitored file
        );

        static std::vector<double> simulate_oisac_channel_feedback(
            double snr_conceptual,     // e.g., based on VM noise/volatility
            double bandwidth_conceptual // e.g., related to page fault rate
        );
    };

    // --- Main Collector Class ---
    class QuectoVirtualMemoryCollector {
    public:
        QuectoVirtualMemoryCollector(const std::string& log_dir, const std::string& monitored_dir);
        ~QuectoVirtualMemoryCollector();

        void start_collection();
        void stop_collection();

    private:
        // Helper functions for Win32 API string conversions
        std::string ConvertWCharToString(const WCHAR* wstr);
        std::wstring ConvertStringToWChar(const std::string& str);

        // Internal collection loops (running in separate threads)
        void snapshot_collector_loop();
        void edge_collector_loop();
        void file_system_collector_loop();
        void file_scanner_loop(); // New loop for periodic scanning

        // PDH Counter functions for system metrics
        bool InitializePdhCounters();
        void ClosePdhCounters();
        void QueryPdhCounters(VirtualMemorySnapshot& snapshot);

        // Process memory hotspot collection
        std::vector<std::pair<std::string, double>> get_process_memory_hotspots();

        // Logging handlers
        void on_qvm_edge_captured(const QVMEdge& edge);
        void on_snapshot_captured(const VirtualMemorySnapshot& snapshot);

        // File entropy analysis (integrated from your provided code)
        // Overload for raw data blocks
        double calculateFileEntropy(const std::vector<unsigned char>& data);
        // Overload for file paths
        double calculateFileEntropy(const std::wstring& filePath);
        bool copyFileToFolder(const std::wstring& sourcePath, const std::wstring& destFolderPath);
        bool isFileSuspicious(const std::wstring& filePath, double& out_entropy); // New suspiciousness check

        std::string log_directory_;
        std::string monitored_code_directory_;
        std::wstring suspicious_files_destination_folder_; // New member for quarantine folder

        std::ofstream edge_log_file_;
        std::ofstream snapshot_log_file_;

        std::atomic<bool> running_ = false;
        std::thread edge_collector_thread_;
        std::thread snapshot_collector_thread_;
        std::thread file_system_collector_thread_;
        std::thread file_scanner_thread_; // New thread for file scanning

        std::mutex log_mutex_; // Protects access to log files

        // PDH counter handles - now correctly typed from Pdh.h
        PDH_HQUERY phQuery_ = NULL;
        PDH_HCOUNTER phTotalCommitBytes_ = NULL;
        PDH_HCOUNTER phAvailableBytes_ = NULL;
        PDH_HCOUNTER phPageFaultsPerSec_ = NULL;
        PDH_HCOUNTER phPagesInputPerSec_ = NULL;
        PDH_HCOUNTER phPagesOutputPerSec_ = NULL;
        PDH_HCOUNTER phCompressedPages_ = NULL;
    };

} // namespace QVMC
