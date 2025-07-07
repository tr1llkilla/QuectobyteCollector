# QuectoVirtualMemoryCollector (QVMC)

**Author:** Cadell Richard Anderson  
**License:** Custom License: Quectobyte Attribution License (QAL) v1.0
**Version:** 0.1  
**Date:** July 2025

// qvmc_collector.cpp
// qvmc_collector.cpp
#include "qvmc_collector.h" // Includes Windows.h, Pdh.h, and Psapi.h now
#include <iostream>
#include <algorithm>
#include <chrono>
#include <cmath> // For std::log, std::exp
#include <vector>
#include <string>
#include <sstream>
#include <filesystem>
#include <numeric> // For std::accumulate
#include <iomanip> // For std::fixed, std::setprecision
#include <unordered_map> // For calculateFileEntropy

// Linker directives for required libraries (these should be in project settings, but harmless here)
#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Psapi.lib") // Explicitly link Psapi.lib
#pragma comment(lib, "Advapi32.lib") // Often needed for security functions, though not directly used for process info here

namespace QVMC {

    // --- Helper function to convert WCHAR* to std::string ---
    // Corrected to take const WCHAR*
    std::string QuectoVirtualMemoryCollector::ConvertWCharToString(const WCHAR* wstr) {
        if (!wstr) return "";
        // Calculate the required buffer size (including null terminator)
        int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
        if (len == 0) return ""; // Handle error or empty string

        // Convert wide char string to multi-byte string (UTF-8)
        std::string str(len - 1, '\0'); // len includes null terminator, so size is len-1
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], len, NULL, NULL);
        return str;
    }

    // --- Helper to convert std::string to std::wstring ---
    std::wstring QuectoVirtualMemoryCollector::ConvertStringToWChar(const std::string& str) {
        if (str.empty()) return L"";
        // Calculate the required buffer size (including null terminator)
        int num_chars = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
        if (num_chars == 0) return L""; // Handle error or empty string

        std::wstring wstr(num_chars - 1, L'\0'); // num_chars includes null terminator
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], num_chars);
        return wstr;
    }

    // --- QVMNode XML Serialization ---
    std::string QVMNode::toXML() const {
        std::ostringstream oss;
        oss << "<QVMNode>\n";
        oss << "  <ID>" << id << "</ID>\n";
        oss << "  <Type>" << type << "</Type>\n";
        oss << "  <Name>" << name << "</Name>\n";
        oss << "  <CommittedBytes>" << current_committed_bytes << "</CommittedBytes>\n";
        oss << "  <PeakCommittedBytes>" << peak_committed_bytes << "</PeakCommittedBytes>\n";
        oss << "</QVMNode>";
        return oss.str();
    }

    // --- QVMEdge XML Serialization (UPDATED) ---
    std::string QVMEdge::toXML() const {
        std::ostringstream oss;
        oss << "<QVMEdge>\n";
        oss << "  <Timestamp>" << std::chrono::duration_cast<std::chrono::milliseconds>(timestamp.time_since_epoch()).count() << "</Timestamp>\n";
        oss << "  <SourceNodeID>" << source_node_id << "</SourceNodeID>\n";
        oss << "  <TargetNodeID>" << target_node_id << "</TargetNodeID>\n";
        oss << "  <TranscendentalCouplingMetrics>";
        for (size_t i = 0; i < transcendental_coupling_metrics.size(); ++i) {
            oss << std::fixed << std::setprecision(4) << transcendental_coupling_metrics[i] << (i < transcendental_coupling_metrics.size() - 1 ? "," : "");
        }
        oss << "</TranscendentalCouplingMetrics>\n";
        oss << "  <ContextTags>\n";
        for (const auto& tag : context_tags)
            oss << "    <Tag>" << tag << "</Tag>\n";
        oss << "  </ContextTags>\n";
        oss << "</QVMEdge>\n";
        return oss.str();
    }

    // --- VirtualMemorySnapshot XML Serialization ---
    std::string VirtualMemorySnapshot::toXML() const {
        auto vec_to_str = [](const std::vector<double>& vec) {
            std::ostringstream oss;
            for (size_t i = 0; i < vec.size(); ++i)
                oss << std::fixed << std::setprecision(4) << vec[i] << (i < vec.size() - 1 ? "," : "");
            return oss.str();
            };

        std::ostringstream oss;
        oss << "<VirtualMemorySnapshot>\n";
        oss << "  <Timestamp>" << std::chrono::duration_cast<std::chrono::milliseconds>(timestamp.time_since_epoch()).count() << "</Timestamp>\n";
        oss << "  <SystemMetrics>\n";
        oss << "    <CommitBytesTotal>" << std::fixed << std::setprecision(0) << system_commit_bytes_total << "</CommitBytesTotal>\n";
        oss << "    <AvailableBytes>" << std::fixed << std::setprecision(0) << system_available_bytes << "</AvailableBytes>\n";
        oss << "    <PageFaultsPerSec>" << std::fixed << std::setprecision(2) << system_page_faults_per_sec << "</PageFaultsPerSec>\n";
        oss << "    <PagesInputPerSec>" << std::fixed << std::setprecision(2) << system_pages_input_per_sec << "</PagesInputPerSec>\n";
        oss << "    <PagesOutputPerSec>" << std::fixed << std::setprecision(2) << system_pages_output_per_sec << "</PagesOutputPerSec>\n";
        oss << "    <CompressedPagesTotal>" << std::fixed << std::setprecision(0) << system_compressed_pages_total << "</CompressedPagesTotal>\n";
        oss << "  </SystemMetrics>\n";
        oss << "  <DerivedMaps>\n";
        oss << "    <EntropyMap>" << vec_to_str(entropy_map_derived) << "</EntropyMap>\n";
        oss << "    <VolatilityMap>" << vec_to_str(volatility_map_derived) << "</VolatilityMap>\n";
        oss << "  </DerivedMaps>\n";
        oss << "  <AccessHeatmap>\n";
        for (const auto& hotspot : process_memory_hotspots) {
            oss << "    <Process HotspotName=\"" << hotspot.first << "\" Metric=\"" << std::fixed << std::setprecision(0) << hotspot.second << "\"/>\n";
        }
        oss << "  </AccessHeatmap>\n";
        oss << "</VirtualMemorySnapshot>\n";
        return oss.str();
    }

    // --- TranscendentalInformationLayer (TIL) Implementation ---
    double TranscendentalInformationLayer::calculate_shannon_entropy_ln(const std::vector<double>& probabilities) {
        double entropy = 0.0;
        for (double p : probabilities) {
            if (p > 0.0) { // log(0) is undefined
                entropy -= p * std::log(p); // Use natural log (base e)
            }
        }
        return entropy;
    }

    double TranscendentalInformationLayer::calculate_kl_divergence(const std::vector<double>& p, const std::vector<double>& q) {
        if (p.size() != q.size()) {
            std::cerr << "KL Divergence: Probability distributions must have the same size." << std::endl;
            return 0.0;
        }

        double divergence = 0.0;
        for (size_t i = 0; i < p.size(); ++i) {
            if (p[i] > 0.0 && q[i] > 0.0) {
                divergence += p[i] * std::log(p[i] / q[i]); // Use natural log
            }
            else if (p[i] > 0.0 && q[i] == 0.0) {
                return std::numeric_limits<double>::infinity();
            }
        }
        return divergence;
    }

    double TranscendentalInformationLayer::calculate_e_factor_change(double initial_value, double change_rate, double time_delta) {
        return initial_value * std::exp(change_rate * time_delta);
    }

    std::vector<double> TranscendentalInformationLayer::derive_transcendental_coupling_metrics(
        const std::vector<std::string>& context_tags,
        double vm_change_magnitude,
        double file_change_magnitude,
        double file_entropy) { // New parameter

        // Metric 1: Conceptual Information Volatility (e-based decay of stability)
        double vm_volatility_factor = vm_change_magnitude / (1024.0 * 1024.0 * 50.0); // Scale 50MB
        double file_volatility_factor = file_change_magnitude / (1024.0 * 10.0); // Scale 10KB

        double info_volatility_index = std::exp(std::max(vm_volatility_factor, file_volatility_factor)) - 1.0;
        info_volatility_index = std::min(info_volatility_index, 10.0); // Cap for reasonable range

        // Metric 2: Contextual Entropy Change (e-based uncertainty from tags)
        double entropy_contribution = 0.0;
        for (const auto& tag : context_tags) {
            if (tag == "process_lifecycle" || tag == "file_create" || tag == "file_delete") {
                entropy_contribution += 0.7; // Significant event
            }
            else if (tag == "file_edit" || tag == "paging_sim" || tag == "compression_sim") {
                entropy_contribution += 0.4; // Moderate event
            }
            else if (tag == "network_activity") {
                entropy_contribution += 0.5; // Can be high or low
            }
            else if (tag == "code_file" || tag == "project_config") {
                entropy_contribution += 0.3; // Specific to code changes
            }
            else if (tag == "suspicious_activity") { // New tag for suspicious files
                entropy_contribution += 1.0; // High impact
            }
        }
        // Incorporate file entropy directly into contextual entropy change
        entropy_contribution += (file_entropy / 8.0) * 0.5; // Scale entropy (max 8 for byte data) and add as contribution
        double contextual_entropy_change = std::exp(entropy_contribution / 1.5) - 1.0; // Scale for e-growth
        contextual_entropy_change = std::min(contextual_entropy_change, 5.0); // Cap

        // Metric 3: O-ISAC Conceptual Channel Quality (simulated)
        double conceptual_snr = 100.0 / (1.0 + info_volatility_index * 5.0); // Arbitrary scaling
        double conceptual_bandwidth = 1000.0; // Fixed for this simulation
        std::vector<double> oisac_feedback = TranscendentalInformationLayer::simulate_oisac_channel_feedback(
            conceptual_snr, conceptual_bandwidth);
        double oisac_quality_factor = oisac_feedback[0]; // Capacity_ln

        return { info_volatility_index, contextual_entropy_change, oisac_quality_factor };
    }

    std::vector<double> TranscendentalInformationLayer::simulate_oisac_channel_feedback(
        double snr_conceptual, double bandwidth_conceptual) {
        double capacity_ln = bandwidth_conceptual * std::log(1.0 + snr_conceptual);
        double conceptual_ber = std::exp(-snr_conceptual / 15.0);

        double six_phase_boost_factor = 1.15; // 15% conceptual improvement for capacity
        capacity_ln *= six_phase_boost_factor;
        conceptual_ber /= six_phase_boost_factor;

        return { capacity_ln, conceptual_ber };
    }

    // --- QuectoVirtualMemoryCollector Constructor / Destructor ---
    QuectoVirtualMemoryCollector::QuectoVirtualMemoryCollector(const std::string& log_dir, const std::string& monitored_dir)
        : log_directory_(log_dir), phQuery_(NULL),
        monitored_code_directory_(monitored_dir)
    {
        // Set the suspicious files destination folder
        // IMPORTANT: Change this path to a valid, accessible directory on your system for testing.
        suspicious_files_destination_folder_ = L"C:\\Users\\Noob\\OneDrive\\Desktop\\Desktop\\ScanSuspisciousResults\\bigscan1"; // Default for example

        std::filesystem::create_directories(log_directory_);
        std::cout << "Attempting to open edge log file: " << log_directory_ + "/qvm_edges.xml" << std::endl;
        edge_log_file_.open(log_directory_ + "/qvm_edges.xml");
        if (!edge_log_file_.is_open()) {
            std::cerr << "ERROR: Failed to open edge log file!" << std::endl;
        }
        else {
            std::cout << "Edge log file opened successfully." << std::endl;
        }

        std::cout << "Attempting to open snapshot log file: " << log_directory_ + "/vm_snapshots.xml" << std::endl;
        snapshot_log_file_.open(log_directory_ + "/vm_snapshots.xml");
        if (!snapshot_log_file_.is_open()) {
            std::cerr << "ERROR: Failed to open snapshot log file!" << std::endl;
        }
        else {
            std::cout << "Snapshot log file opened successfully." << std::endl;
        }

        if (!InitializePdhCounters()) {
            std::cerr << "Failed to initialize PDH counters. System snapshots may be incomplete." << std::endl;
        }
    }

    QuectoVirtualMemoryCollector::~QuectoVirtualMemoryCollector() {
        stop_collection();
        ClosePdhCounters();
        if (edge_log_file_.is_open()) edge_log_file_.close();
        if (snapshot_log_file_.is_open()) snapshot_log_file_.close();
    }

    // --- Collection Control ---
    void QuectoVirtualMemoryCollector::start_collection() {
        if (running_) {
            std::cerr << "Collection already running." << std::endl;
            return;
        }
        running_ = true;
        edge_collector_thread_ = std::thread(&QuectoVirtualMemoryCollector::edge_collector_loop, this);
        snapshot_collector_thread_ = std::thread(&QuectoVirtualMemoryCollector::snapshot_collector_loop, this);
        file_system_collector_thread_ = std::thread(&QuectoVirtualMemoryCollector::file_system_collector_loop, this);
        file_scanner_thread_ = std::thread(&QuectoVirtualMemoryCollector::file_scanner_loop, this); // Start new scanner thread
    }

    void QuectoVirtualMemoryCollector::stop_collection() {
        if (!running_) {
            std::cerr << "Collection not running." << std::endl;
            return;
        }
        running_ = false;
        if (edge_collector_thread_.joinable()) edge_collector_thread_.join();
        if (snapshot_collector_thread_.joinable()) snapshot_collector_thread_.join();
        if (file_system_collector_thread_.joinable()) file_system_collector_thread_.join();
        if (file_scanner_thread_.joinable()) file_scanner_thread_.join(); // Join scanner thread
    }

    // --- Logging Handlers ---
    void QuectoVirtualMemoryCollector::on_qvm_edge_captured(const QVMEdge& edge) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        edge_log_file_ << edge.toXML() << std::endl;
    }

    void QuectoVirtualMemoryCollector::on_snapshot_captured(const VirtualMemorySnapshot& snapshot) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        snapshot_log_file_ << snapshot.toXML() << std::endl;
    }

    // --- PDH API Implementation ---
    bool QuectoVirtualMemoryCollector::InitializePdhCounters() {
        PDH_STATUS status;

        status = PdhOpenQueryW(NULL, NULL, &phQuery_);
        if (status != ERROR_SUCCESS) {
            std::wcerr << L"PdhOpenQueryW failed with status 0x" << std::hex << status << std::endl;
            return false;
        }

        status = PdhAddCounterW(phQuery_, L"\\Memory\\Committed Bytes", NULL, &phTotalCommitBytes_);
        if (status != ERROR_SUCCESS) { std::wcerr << L"PdhAddCounterW (Committed Bytes) failed: 0x" << std::hex << status << std::endl; ClosePdhCounters(); return false; }

        status = PdhAddCounterW(phQuery_, L"\\Memory\\Available Bytes", NULL, &phAvailableBytes_);
        if (status != ERROR_SUCCESS) { std::wcerr << L"PdhAddCounterW (Available Bytes) failed: 0x" << std::hex << status << std::endl; ClosePdhCounters(); return false; }

        status = PdhAddCounterW(phQuery_, L"\\Memory\\Page Faults/sec", NULL, &phPageFaultsPerSec_);
        if (status != ERROR_SUCCESS) { std::wcerr << L"PdhAddCounterW (Page Faults/sec) failed: 0x" << std::hex << status << std::endl; ClosePdhCounters(); return false; }

        status = PdhAddCounterW(phQuery_, L"\\Memory\\Pages Input/sec", NULL, &phPagesInputPerSec_);
        if (status != ERROR_SUCCESS) { std::wcerr << L"PdhAddCounterW (Pages Input/sec) failed: 0x" << std::hex << status << std::endl; ClosePdhCounters(); return false; }

        status = PdhAddCounterW(phQuery_, L"\\Memory\\Pages Output/sec", NULL, &phPagesOutputPerSec_);
        if (status != ERROR_SUCCESS) { std::wcerr << L"PdhAddCounterW (Pages Output/sec) failed: 0x" << std::hex << status << std::endl; ClosePdhCounters(); return false; }

        status = PdhAddCounterW(phQuery_, L"\\Memory\\Compressed Bytes", NULL, &phCompressedPages_);
        if (status != ERROR_SUCCESS) {
            std::wcerr << L"Warning: PdhAddCounterW (Compressed Bytes) failed: 0x" << std::hex << status << std::endl;
            phCompressedPages_ = NULL; // Set to NULL to avoid using an invalid handle later
        }

        status = PdhCollectQueryData(phQuery_);
        if (status != ERROR_SUCCESS) {
            std::wcerr << L"PdhCollectQueryData (initial) failed: 0x" << std::hex << status << std::endl;
            ClosePdhCounters();
            return false;
        }
        return true;
    }

    void QuectoVirtualMemoryCollector::ClosePdhCounters() {
        if (phQuery_ != NULL) {
            PdhCloseQuery(phQuery_);
            phQuery_ = NULL;
        }
    }

    void QuectoVirtualMemoryCollector::QueryPdhCounters(VirtualMemorySnapshot& snapshot) {
        PDH_STATUS status;
        PDH_FMT_COUNTERVALUE counterValue;

        status = PdhCollectQueryData(phQuery_);
        if (status != ERROR_SUCCESS) {
            std::wcerr << L"PdhCollectQueryData failed: 0x" << std::hex << status << std::endl;
            snapshot.system_commit_bytes_total = 0;
            snapshot.system_available_bytes = 0;
            snapshot.system_page_faults_per_sec = 0;
            snapshot.system_pages_input_per_sec = 0;
            snapshot.system_pages_output_per_sec = 0;
            snapshot.system_compressed_pages_total = 0;
            snapshot.entropy_map_derived.clear();
            snapshot.volatility_map_derived.clear();
            snapshot.process_memory_hotspots.clear();
            return;
        }

        if (phTotalCommitBytes_ != NULL) {
            status = PdhGetFormattedCounterValue(phTotalCommitBytes_, PDH_FMT_LARGE | PDH_FMT_NOCAP100, NULL, &counterValue);
            if (status == ERROR_SUCCESS) snapshot.system_commit_bytes_total = static_cast<double>(counterValue.largeValue);
            else std::wcerr << L"PdhGetFormattedCounterValue (Committed Bytes) failed: 0x" << std::hex << status << std::endl;
        }

        if (phAvailableBytes_ != NULL) {
            status = PdhGetFormattedCounterValue(phAvailableBytes_, PDH_FMT_LARGE | PDH_FMT_NOCAP100, NULL, &counterValue);
            if (status == ERROR_SUCCESS) snapshot.system_available_bytes = static_cast<double>(counterValue.largeValue);
            else std::wcerr << L"PdhGetFormattedCounterValue (Available Bytes) failed: 0x" << std::hex << status << std::endl;
        }

        if (phPageFaultsPerSec_ != NULL) {
            status = PdhGetFormattedCounterValue(phPageFaultsPerSec_, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, NULL, &counterValue);
            if (status == ERROR_SUCCESS) snapshot.system_page_faults_per_sec = counterValue.doubleValue;
            else std::wcerr << L"PdhGetFormattedCounterValue (Page Faults/sec) failed: 0x" << std::hex << status << std::endl;
        }

        if (phPagesInputPerSec_ != NULL) {
            status = PdhGetFormattedCounterValue(phPagesInputPerSec_, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, NULL, &counterValue);
            if (status == ERROR_SUCCESS) snapshot.system_pages_input_per_sec = counterValue.doubleValue;
            else std::wcerr << L"PdhGetFormattedCounterValue (Pages Input/sec) failed: 0x" << std::hex << status << std::endl;
        }

        if (phPagesOutputPerSec_ != NULL) {
            status = PdhGetFormattedCounterValue(phPagesOutputPerSec_, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, NULL, &counterValue);
            if (status == ERROR_SUCCESS) snapshot.system_pages_output_per_sec = counterValue.doubleValue;
            else std::wcerr << L"PdhGetFormattedCounterValue (Pages Output/sec) failed: 0x" << std::hex << status << std::endl;
        }

        if (phCompressedPages_ != NULL) {
            status = PdhGetFormattedCounterValue(phCompressedPages_, PDH_FMT_LARGE | PDH_FMT_NOCAP100, NULL, &counterValue);
            if (status == ERROR_SUCCESS) snapshot.system_compressed_pages_total = static_cast<double>(counterValue.largeValue);
            else std::wcerr << L"PdhGetFormattedCounterValue (Compressed Bytes) failed: 0x" << std::hex << status << std::endl;
        }
    }

    // --- Process Memory Hotspot Collection ---
    std::vector<std::pair<std::string, double>> QuectoVirtualMemoryCollector::get_process_memory_hotspots() {
        std::vector<std::pair<std::string, double>> hotspots;
        DWORD aProcesses[1024], cbNeeded, cProcesses;

        if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
            std::cerr << "ERROR: EnumProcesses failed. Error code: " << GetLastError() << std::endl;
            return hotspots;
        }

        cProcesses = cbNeeded / sizeof(DWORD);
        for (unsigned int i = 0; i < cProcesses; i++) {
            if (aProcesses[i] == 0) continue;

            // Use PROCESS_QUERY_INFORMATION | PROCESS_VM_READ for process info and memory counters
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
            if (hProcess == NULL) continue; // Skip if process cannot be opened

            WCHAR szProcessName[MAX_PATH] = L"<unknown>"; // Use WCHAR directly
            HMODULE hMod;
            DWORD cb;
            // GetModuleBaseNameW is the wide-character version
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cb)) {
                GetModuleBaseNameW(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(WCHAR));
            }

            PROCESS_MEMORY_COUNTERS pmc; // Correctly declared
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                // Correctly convert WCHAR* to std::string before pushing back
                hotspots.push_back({ ConvertWCharToString(szProcessName), static_cast<double>(pmc.WorkingSetSize) });
            }

            CloseHandle(hProcess);
        }

        std::sort(hotspots.begin(), hotspots.end(), [](const auto& a, const auto& b) {
            return a.second > b.second;
            });

        const size_t MAX_HOTSPOTS = 10;
        if (hotspots.size() > MAX_HOTSPOTS) {
            hotspots.resize(MAX_HOTSPOTS);
        }

        return hotspots;
    }

    // --- File Entropy Analysis (Integrated and Modified) ---
    // Constants
    constexpr size_t BLOCK_SIZE = 4096;

    // Calculate Shannon entropy (using natural log for base-e conceptual alignment)
    double QuectoVirtualMemoryCollector::calculateFileEntropy(const std::vector<unsigned char>& data) {
        if (data.empty()) return 0.0; // Handle empty data to avoid division by zero or log(0)

        std::unordered_map<unsigned char, size_t> freq;
        for (unsigned char byte : data) freq[byte]++;

        double entropy = 0.0;
        for (const auto& pair : freq) {
            double p = static_cast<double>(pair.second) / data.size();
            // Use natural logarithm (std::log) for base-e derived entropy
            entropy -= p * std::log(p);
        }
        return entropy;
    }

    // Overload for file paths - calls the raw data version
    double QuectoVirtualMemoryCollector::calculateFileEntropy(const std::wstring& filePath) {
        // Check if the path exists and is a regular file
        if (!std::filesystem::exists(filePath) || !std::filesystem::is_regular_file(filePath)) {
            // std::wcerr << L"[-] Path does not exist or is not a regular file: " << filePath << L"\n";
            return 0.0;
        }

        FILE* fp = nullptr;
        errno_t err = _wfopen_s(&fp, filePath.c_str(), L"rb");
        if (err != 0 || !fp) {
            // std::wcerr << L"[-] Cannot open: " << filePath << L" (Error: " << err << L")\n"; // Suppress frequent errors
            return 0.0; // Return 0 entropy if file cannot be opened
        }

        size_t blockIndex = 0;
        double totalEntropy = 0.0;
        size_t blockCount = 0;

        std::vector<unsigned char> buffer(BLOCK_SIZE);
        while (true) {
            size_t bytesRead = fread(buffer.data(), 1, BLOCK_SIZE, fp);
            if (bytesRead == 0) break;

            buffer.resize(bytesRead);
            double entropy = this->calculateFileEntropy(buffer); // Correct call to member function
            totalEntropy += entropy;
            blockCount++;
            buffer.resize(BLOCK_SIZE); // Reset buffer size for next read
        }

        fclose(fp);

        if (blockCount == 0) {
            return 0.0; // No data, no entropy
        }

        double avgEntropy = totalEntropy / blockCount;
        return avgEntropy;
    }

    // New helper function to copy files
    bool QuectoVirtualMemoryCollector::copyFileToFolder(const std::wstring& sourcePath, const std::wstring& destFolderPath) {
        // Ensure the destination directory exists
        if (!std::filesystem::exists(destFolderPath)) {
            std::error_code ec;
            if (!std::filesystem::create_directories(destFolderPath, ec)) {
                std::wcerr << L"[-] Failed to create destination directory '" << destFolderPath << L"': " << ec.message().c_str() << L", Error code: " << ec.value() << L"\n";
                return false;
            }
        }

        std::filesystem::path source_fs_path(sourcePath);
        std::filesystem::path dest_fs_path(destFolderPath);
        dest_fs_path /= source_fs_path.filename(); // Append source file name to destination path

        // Copy the file. FALSE means it will fail if the file already exists.
        if (CopyFileW(sourcePath.c_str(), dest_fs_path.c_str(), FALSE)) {
            std::wcout << L"[+] File copied successfully to: " << dest_fs_path.c_str() << L"\n";
            return true;
        }
        else {
            DWORD error = GetLastError();
            std::wcerr << L"[-] CopyFileW failed with error code: " << error << L". (Source: " << sourcePath << L", Dest: " << dest_fs_path.c_str() << L")\n";
            if (error == ERROR_FILE_EXISTS) {
                std::wcerr << L"    File already exists in the destination folder.\n";
            }
            return false;
        }
    }

    // New function to determine if a file is suspicious
    bool QuectoVirtualMemoryCollector::isFileSuspicious(const std::wstring& filePath, double& out_entropy) {
        out_entropy = this->calculateFileEntropy(filePath);

        // Simple heuristic: high entropy could indicate packed/encrypted malware
        // A common threshold for high entropy in byte streams is > 5.0 (out of ~5.545 max for natural log)
        if (out_entropy > 5.0) { // Adjusted threshold for natural log entropy
            return true;
        }

        // Add other heuristics here if needed, e.g.:
        // - Specific file extensions known for malware (.exe, .dll, .scr, but also less common ones)
        // - Files with unusual sizes (e.g., extremely small executables)
        // - Files in unusual locations (e.g., .exe in AppData temp folders)
        // - Files that are constantly being written to with high page faults (from VM metrics)

        return false;
    }


    // --- Collector Loops (UPDATED for TIL integration) ---
    void QuectoVirtualMemoryCollector::snapshot_collector_loop() {
        while (running_) {
            VirtualMemorySnapshot snapshot;
            snapshot.timestamp = std::chrono::system_clock::now();

            QueryPdhCounters(snapshot);
            snapshot.process_memory_hotspots = get_process_memory_hotspots();

            double total_memory = snapshot.system_commit_bytes_total + snapshot.system_available_bytes;
            if (total_memory > 0) {
                std::vector<double> vm_probs = {
                    snapshot.system_commit_bytes_total / total_memory,
                    snapshot.system_available_bytes / total_memory
                };
                snapshot.entropy_map_derived.push_back(TranscendentalInformationLayer::calculate_shannon_entropy_ln(vm_probs));
                double vm_change_rate = (snapshot.system_page_faults_per_sec + snapshot.system_pages_input_per_sec + snapshot.system_pages_output_per_sec) / 1000.0;
                snapshot.volatility_map_derived.push_back(TranscendentalInformationLayer::calculate_e_factor_change(1.0, vm_change_rate, 1.0) - 1.0);
            }
            else {
                snapshot.entropy_map_derived.push_back(0.0);
                snapshot.volatility_map_derived.push_back(0.0);
            }
            if (snapshot.entropy_map_derived.size() > 5) snapshot.entropy_map_derived.erase(snapshot.entropy_map_derived.begin());
            if (snapshot.volatility_map_derived.size() > 5) snapshot.volatility_map_derived.erase(snapshot.volatility_map_derived.begin());


            std::cout << "Snapshot collected (timestamp: "
                << std::chrono::duration_cast<std::chrono::seconds>(snapshot.timestamp.time_since_epoch()).count()
                << "), Commit Bytes: " << std::fixed << std::setprecision(0) << snapshot.system_commit_bytes_total
                << ", Available Bytes: " << std::fixed << std::setprecision(0) << snapshot.system_available_bytes
                << ", Page Faults/sec: " << std::fixed << std::setprecision(2) << snapshot.system_page_faults_per_sec
                << ", Hotspots Count: " << snapshot.process_memory_hotspots.size()
                << ", Derived Entropy(ln): " << std::fixed << std::setprecision(4) << snapshot.entropy_map_derived.back()
                << ", Derived Volatility(e-factor): " << std::fixed << std::setprecision(4) << snapshot.volatility_map_derived.back()
                << std::endl;

            on_snapshot_captured(snapshot);
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }

    void QuectoVirtualMemoryCollector::edge_collector_loop() {
        std::map<DWORD, std::string> known_processes;
        std::map<DWORD, double> last_process_working_set_size;

        while (running_) {
            DWORD aProcesses[1024], cbNeeded, cProcesses;
            if (EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
                cProcesses = cbNeeded / sizeof(DWORD);
                std::map<DWORD, std::string> current_processes;
                for (unsigned int i = 0; i < cProcesses; i++) {
                    if (aProcesses[i] == 0) continue;
                    // Use PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
                    if (hProcess) {
                        WCHAR szProcessName[MAX_PATH] = L"<unknown>";
                        HMODULE hMod;
                        DWORD cb;
                        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cb)) {
                            GetModuleBaseNameW(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(WCHAR));
                        }
                        current_processes[aProcesses[i]] = ConvertWCharToString(szProcessName);

                        PROCESS_MEMORY_COUNTERS pmc; // Correctly declared
                        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                            double current_wss = static_cast<double>(pmc.WorkingSetSize);
                            last_process_working_set_size[aProcesses[i]] = current_wss;
                        }
                        CloseHandle(hProcess);
                    }
                }

                for (const auto& pair : current_processes) {
                    if (known_processes.find(pair.first) == known_processes.end()) {
                        // Process started
                        QVMEdge edge;
                        edge.timestamp = std::chrono::system_clock::now();
                        edge.source_node_id = "OS_Kernel";
                        edge.target_node_id = "Process_" + std::to_string(pair.first);
                        edge.context_tags = { "process_lifecycle", "start", pair.second };

                        double vm_change = last_process_working_set_size.count(pair.first) ? last_process_working_set_size[pair.first] : 0.0;
                        edge.transcendental_coupling_metrics =
                            TranscendentalInformationLayer::derive_transcendental_coupling_metrics(
                                edge.context_tags, vm_change, 0.0, 0.0); // No file entropy for process start
                        on_qvm_edge_captured(edge);
                        std::cout << "Edge captured: Process '" << pair.second << "' (ID: " << pair.first
                            << ") started. TCM: [" << std::fixed << std::setprecision(4) << edge.transcendental_coupling_metrics[0] << ", "
                            << edge.transcendental_coupling_metrics[1] << ", "
                            << edge.transcendental_coupling_metrics[2] << "]" << std::endl;
                    }
                }

                for (const auto& pair : known_processes) {
                    if (current_processes.find(pair.first) == current_processes.end()) {
                        // Process stopped
                        QVMEdge edge;
                        edge.timestamp = std::chrono::system_clock::now();
                        edge.source_node_id = "Process_" + std::to_string(pair.first);
                        edge.target_node_id = "OS_Kernel";
                        edge.context_tags = { "process_lifecycle", "stop", pair.second };

                        edge.transcendental_coupling_metrics =
                            TranscendentalInformationLayer::derive_transcendental_coupling_metrics(
                                edge.context_tags, 0.0, 0.0, 0.0); // Use 0 for change magnitude as process is gone
                        on_qvm_edge_captured(edge);
                        std::cout << "Edge captured: Process '" << pair.second << "' (ID: " << pair.first
                            << ") stopped. TCM: [" << std::fixed << std::setprecision(4) << edge.transcendental_coupling_metrics[0] << ", "
                            << edge.transcendental_coupling_metrics[1] << ", "
                            << edge.transcendental_coupling_metrics[2] << "]" << std::endl;
                    }
                }
                known_processes = current_processes;
            }
            else {
                std::cerr << "ERROR: EnumProcesses failed in edge_collector_loop. Error code: " << GetLastError() << std::endl;
            }

            // Synthetic VM interaction edge, now also using TIL
            QVMEdge edge;
            edge.source_node_id = "VM_System_Insight";
            edge.target_node_id = "Conceptual_OISAC_Path";
            edge.timestamp = std::chrono::system_clock::now();
            edge.context_tags = { "paging_sim", "compression_sim", "system_idle_analysis" };

            double conceptual_vm_change = std::sin(std::chrono::duration_cast<std::chrono::seconds>(edge.timestamp.time_since_epoch()).count() / 10.0) * 1000000.0;
            double conceptual_file_change = 0.0;

            edge.transcendental_coupling_metrics =
                TranscendentalInformationLayer::derive_transcendental_coupling_metrics(
                    edge.context_tags, conceptual_vm_change, conceptual_file_change, 0.0); // No file entropy for synthetic VM
            on_qvm_edge_captured(edge);
            std::cout << "Edge captured: Synthetic VM interaction. TCM: ["
                << std::fixed << std::setprecision(4) << edge.transcendental_coupling_metrics[0] << ", "
                << edge.transcendental_coupling_metrics[1] << ", "
                << edge.transcendental_coupling_metrics[2] << "]" << std::endl;

            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }


    // --- File System Monitoring Loop (Real-time, UPDATED with specific message) ---
    void QuectoVirtualMemoryCollector::file_system_collector_loop() {
        if (monitored_code_directory_.empty()) {
            std::cerr << "File system collector: monitored_code_directory_ is not set. Please provide a valid path." << std::endl;
            return;
        }
        std::cout << "File system collector (real-time): Attempting to monitor directory: " << monitored_code_directory_ << std::endl;

        std::wstring w_monitored_code_directory = ConvertStringToWChar(monitored_code_directory_);

        HANDLE hDir = CreateFileW(
            w_monitored_code_directory.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            NULL
        );

        if (hDir == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            std::wcerr << L"File system collector (real-time): CreateFileW failed for directory \""
                << w_monitored_code_directory << L"\" with error " << error << L", LastError: " << GetLastError() << std::endl;
            return;
        }
        else {
            std::cout << "File system collector (real-time): Successfully opened directory handle." << std::endl;
        }

        const DWORD BUFFER_SIZE = 4096;
        alignas(FILE_NOTIFY_INFORMATION) BYTE buffer[BUFFER_SIZE];
        DWORD bytes_returned;
        OVERLAPPED overlapped;
        ZeroMemory(&overlapped, sizeof(overlapped));

        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (overlapped.hEvent == NULL) {
            std::cerr << "File system collector (real-time): CreateEvent failed. LastError: " << GetLastError() << std::endl;
            CloseHandle(hDir);
            return;
        }
        else {
            std::cout << "File system collector (real-time): Event handle created." << std::endl;
        }

        BOOL result = ReadDirectoryChangesW(
            hDir, buffer, BUFFER_SIZE, TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytes_returned, &overlapped, NULL
        );

        if (result == 0 && GetLastError() != ERROR_IO_PENDING) {
            DWORD error = GetLastError();
            std::cerr << "File system collector (real-time): Initial ReadDirectoryChangesW failed with error " << error << std::endl;
            CloseHandle(overlapped.hEvent); CloseHandle(hDir); return;
        }
        else if (result == 0 && GetLastError() == ERROR_IO_PENDING) {
            std::cout << "File system collector (real-time): Initial ReadDirectoryChangesW pending (normal for async operation)." << std::endl;
        }
        else {
            std::cout << "File system collector (real-time): Initial ReadDirectoryChangesW completed synchronously (unexpected for OVERLAPPED)." << std::endl;
        }

        while (running_) {
            // Use a timeout to allow the loop to check `running_` flag periodically
            DWORD wait_status = WaitForSingleObject(overlapped.hEvent, 1000); // 1-second timeout

            if (!running_) break; // Check running_ flag after timeout

            if (wait_status == WAIT_OBJECT_0) {
                if (GetOverlappedResult(hDir, &overlapped, &bytes_returned, FALSE)) {
                    if (bytes_returned > 0) {
                        FILE_NOTIFY_INFORMATION* pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);
                        while (true) {
                            std::string filename = ConvertWCharToString(pNotify->FileName);
                            std::wstring w_filename = ConvertStringToWChar(filename);
                            std::wstring full_path = ConvertStringToWChar(monitored_code_directory_) + L"\\" + w_filename;

                            std::cout << "File system collector (real-time): Detected change - File: " << filename
                                << ", Action: " << pNotify->Action << std::endl;

                            std::string action_type;
                            std::vector<std::string> context_tags;
                            double file_size_change = 0.0;
                            double e_derived_entropy = 0.0;
                            bool is_suspicious = false;

                            switch (pNotify->Action) {
                            case FILE_ACTION_ADDED: action_type = "ADDED"; context_tags.push_back("file_create"); break;
                            case FILE_ACTION_REMOVED: action_type = "REMOVED"; context_tags.push_back("file_delete"); break;
                            case FILE_ACTION_MODIFIED:
                                action_type = "MODIFIED"; context_tags.push_back("file_edit");
                                // Call isFileSuspicious, which also calculates entropy
                                is_suspicious = this->isFileSuspicious(full_path, e_derived_entropy);
                                file_size_change = static_cast<double>(rand() % 10000 + 1); // Random change up to 10KB
                                std::wcout << L"File: " << w_filename << L" | E-Derived Entropy: " << std::fixed << std::setprecision(4) << e_derived_entropy << L"\n";
                                break;
                            case FILE_ACTION_RENAMED_OLD_NAME: action_type = "RENAMED_OLD"; context_tags.push_back("file_rename"); break;
                            case FILE_ACTION_RENAMED_NEW_NAME: action_type = "RENAMED_NEW"; context_tags.push_back("file_rename"); break;
                            default: action_type = "UNKNOWN"; break;
                            }

                            context_tags.push_back("file_system");
                            size_t dot_pos = filename.find_last_of('.');
                            if (dot_pos != std::string::npos) {
                                std::string extension = filename.substr(dot_pos + 1);
                                std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
                                context_tags.push_back(extension);
                                if (extension == "cpp" || extension == "h" || extension == "hpp" || extension == "c" || extension == "cc") {
                                    context_tags.push_back("code_file");
                                }
                                else if (extension == "vcxproj" || extension == "sln") {
                                    context_tags.push_back("project_config");
                                }
                            }

                            if (is_suspicious) {
                                context_tags.push_back("suspicious_activity");
                                // Specific message requested by user
                                std::wcout << L"[!] Alertive entropy detected. Attempting to copy file to quarantine folder...\n";
                                if (copyFileToFolder(full_path, suspicious_files_destination_folder_)) {
                                    std::wcout << L"[+] File copied successfully to: " << suspicious_files_destination_folder_ << L"\n";
                                }
                            }

                            QVMEdge file_edge;
                            file_edge.timestamp = std::chrono::system_clock::now();
                            file_edge.source_node_id = "USER_CADEL_ANDERSON"; // Placeholder user ID
                            file_edge.target_node_id = monitored_code_directory_ + "\\" + filename;
                            file_edge.context_tags = context_tags;

                            file_edge.transcendental_coupling_metrics =
                                TranscendentalInformationLayer::derive_transcendental_coupling_metrics(
                                    file_edge.context_tags, 0.0, file_size_change, e_derived_entropy);

                            this->on_qvm_edge_captured(file_edge);
                            std::cout << "File system edge captured (real-time): " << filename << ". TCM: ["
                                << std::fixed << std::setprecision(4) << file_edge.transcendental_coupling_metrics[0] << ", "
                                << file_edge.transcendental_coupling_metrics[1] << ", "
                                << file_edge.transcendental_coupling_metrics[2] << "]" << std::endl;

                            if (pNotify->NextEntryOffset == 0) break;
                            pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>((BYTE*)pNotify + pNotify->NextEntryOffset);
                        }
                    }
                    else { std::cout << "File system collector (real-time): GetOverlappedResult returned 0 bytes, no changes processed." << std::endl; }
                    ResetEvent(overlapped.hEvent);

                    result = ReadDirectoryChangesW(
                        hDir, buffer, BUFFER_SIZE, TRUE,
                        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                        FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                        &bytes_returned, &overlapped, NULL
                    );

                    if (result == 0 && GetLastError() != ERROR_IO_PENDING) {
                        DWORD error = GetLastError(); std::cerr << "File system collector (real-time): Reissuing ReadDirectoryChangesW failed with error " << error << std::endl; break;
                    }
                    else if (result == 0 && GetLastError() == ERROR_IO_PENDING) {
                        // std::cout << "File system collector (real-time): ReadDirectoryChangesW reissued and pending." << std::endl;
                    }
                    else {
                        std::cout << "File system collector (real-time): ReadDirectoryChangesW reissued and completed synchronously." << std::endl;
                    }

                }
                else {
                    DWORD error = GetLastError(); std::cerr << "File system collector (real-time): GetOverlappedResult failed with error " << error << std::endl; break;
                }
            }
            else if (wait_status == WAIT_TIMEOUT) {
                // Timeout occurred, check running_ flag again and re-enter wait
                // std::cout << "File system collector (real-time): Timeout, re-checking running status." << std::endl;
            }
            else {
                DWORD error = GetLastError(); std::cerr << "File system collector (real-time): WaitForSingleObject failed with error " << error << std::endl; break;
            }
        }
        CloseHandle(overlapped.hEvent);
        CloseHandle(hDir);
        std::cout << "File system collector (real-time) stopped." << std::endl;
    }

    // --- New File Scanner Loop (Periodic Background Scan, UPDATED with specific message) ---
    void QuectoVirtualMemoryCollector::file_scanner_loop() {
        if (monitored_code_directory_.empty()) {
            std::cerr << "File scanner: monitored_code_directory_ is not set. Please provide a valid path." << std::endl;
            return;
        }
        std::cout << "File scanner: Starting periodic scan of directory: " << monitored_code_directory_ << std::endl;

        std::filesystem::path root_path(ConvertStringToWChar(monitored_code_directory_));

        while (running_) {
            std::cout << "File scanner: Performing a full scan of '" << monitored_code_directory_ << "'..." << std::endl;
            try {
                // Use recursive_directory_iterator to traverse all files and subdirectories
                for (const auto& entry : std::filesystem::recursive_directory_iterator(
                    root_path, std::filesystem::directory_options::skip_permission_denied)) {

                    if (!running_) break; // Allow stopping during scan

                    if (std::filesystem::is_regular_file(entry.status())) {
                        std::wstring file_path = entry.path().wstring();
                        double current_entropy = 0.0;

                        // Check if the file is suspicious
                        if (isFileSuspicious(file_path, current_entropy)) {
                            // Specific message requested by user
                            std::wcout << L"[!] Alertive entropy detected. Attempting to copy file to quarantine folder...\n";

                            std::vector<std::string> context_tags = { "file_scan", "suspicious_activity", "high_entropy" };
                            // Add file extension as a tag
                            std::string filename_str = ConvertWCharToString(entry.path().filename().c_str());
                            size_t dot_pos = filename_str.find_last_of('.');
                            if (dot_pos != std::string::npos) {
                                std::string extension = filename_str.substr(dot_pos + 1);
                                std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
                                context_tags.push_back(extension);
                            }

                            QVMEdge scan_edge;
                            scan_edge.timestamp = std::chrono::system_clock::now();
                            scan_edge.source_node_id = "QVM_Scanner";
                            scan_edge.target_node_id = ConvertWCharToString(file_path.c_str());
                            scan_edge.context_tags = context_tags;

                            // Derive TCM with file entropy
                            scan_edge.transcendental_coupling_metrics =
                                TranscendentalInformationLayer::derive_transcendental_coupling_metrics(
                                    scan_edge.context_tags, 0.0, 0.0, current_entropy); // No VM/file size change for scan

                            this->on_qvm_edge_captured(scan_edge);
                            std::cout << "File scan edge captured: " << ConvertWCharToString(file_path.c_str()) << ". TCM: ["
                                << std::fixed << std::setprecision(4) << scan_edge.transcendental_coupling_metrics[0] << ", "
                                << scan_edge.transcendental_coupling_metrics[1] << ", "
                                << scan_edge.transcendental_coupling_metrics[2] << "]" << std::endl;

                            // Copy suspicious file and print success message
                            if (copyFileToFolder(file_path, suspicious_files_destination_folder_)) {
                                std::wcout << L"[+] File copied successfully to: " << suspicious_files_destination_folder_ << L"\n";
                            }
                        }
                    }
                }
            }
            catch (const std::filesystem::filesystem_error& e) {
                std::cerr << "File scanner: Filesystem error during scan: " << e.what() << std::endl;
            }
            catch (const std::exception& e) {
                std::cerr << "File scanner: An unexpected error occurred during scan: " << e.what() << std::endl;
            }

            // Sleep for a longer interval before the next full scan (e.g., every 60 seconds)
            std::this_thread::sleep_for(std::chrono::seconds(60));
        }
        std::cout << "File scanner stopped." << std::endl;
    }

} // namespace QVMC
