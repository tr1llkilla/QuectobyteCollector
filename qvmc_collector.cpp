// qvmc_collector.cpp
#include "qvmc_collector.h"
#include <iostream> // For error logging (can replace with a proper logging framework later)
#include <algorithm>
#include <chrono>
#include <cmath>
#include <vector>
#include <string>
#include <sstream>
#include <filesystem>

// Win32 API specific includes for string conversions and ReadDirectoryChangesW
#include <windows.h>
#include <Psapi.h>
#include <Pdh.h>
#include <winnt.h> // For FILE_NOTIFY_INFORMATION

// Linker directives for required libraries (already in .h, but doesn't hurt here)
#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Psapi.lib")

namespace QVMC {

    // --- Helper function to convert WCHAR* to std::string ---
    // This is crucial for handling process names from Win32 API (TCHAR)
    std::string ConvertWCharToString(const WCHAR* wstr) {
        if (!wstr) return "";
        // Calculate the required buffer size
        int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
        if (len == 0) return ""; // Handle error or empty string

        // Convert wide char string to multi-byte string (UTF-8)
        std::string str(len - 1, '\0'); // len includes null terminator, so size is len-1
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], len, NULL, NULL);
        return str;
    }

    // --- Helper to convert std::string to std::wstring (needed for Win32 W functions like CreateFileW) ---
    std::wstring ConvertStringToWChar(const std::string& str) {
        if (str.empty()) return L"";
        int num_chars = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
        if (num_chars == 0) return L""; // Handle error or empty string

        std::wstring wstr(num_chars - 1, L'\0'); // num_chars includes null terminator
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], num_chars);
        return wstr;
    }

    // --- QVMNode XML Serialization (if needed) ---
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

    // --- QVMEdge XML Serialization ---
    std::string QVMEdge::toXML() const {
        std::ostringstream oss;
        oss << "<QVMEdge>\n";
        oss << "  <Timestamp>" << std::chrono::duration_cast<std::chrono::milliseconds>(timestamp.time_since_epoch()).count() << "</Timestamp>\n";
        oss << "  <SourceNodeID>" << source_node_id << "</SourceNodeID>\n";
        oss << "  <TargetNodeID>" << target_node_id << "</TargetNodeID>\n";
        oss << "  <CouplingMatrix>\n";
        for (const auto& row : quecto_coupling_matrix) {
            oss << "    <Row>";
            for (size_t i = 0; i < row.size(); ++i)
                oss << row[i] << (i < row.size() - 1 ? "," : "");
            oss << "</Row>\n";
        }
        oss << "  </CouplingMatrix>\n";
        oss << "  <ContextTags>\n";
        for (const auto& tag : context_tags)
            oss << "    <Tag>" << tag << "</Tag>\n";
        oss << "  </ContextTags>\n";
        oss << "</QVMEdge>\n";
        return oss.str();
    }

    // --- VirtualMemorySnapshot XML Serialization ---
    // Ensure this is properly scoped and matches the header declaration (const)
    std::string VirtualMemorySnapshot::toXML() const { // IMPORTANT: 'const' keyword and 'VirtualMemorySnapshot::' scope
        auto vec_to_str = [](const std::vector<double>& vec) {
            std::ostringstream oss;
            for (size_t i = 0; i < vec.size(); ++i)
                oss << vec[i] << (i < vec.size() - 1 ? "," : "");
            return oss.str();
            };

        std::ostringstream oss;
        oss << "<VirtualMemorySnapshot>\n";
        oss << "  <Timestamp>" << std::chrono::duration_cast<std::chrono::milliseconds>(timestamp.time_since_epoch()).count() << "</Timestamp>\n";
        oss << "  <SystemMetrics>\n";
        oss << "    <CommitBytesTotal>" << system_commit_bytes_total << "</CommitBytesTotal>\n";
        oss << "    <AvailableBytes>" << system_available_bytes << "</AvailableBytes>\n";
        oss << "    <PageFaultsPerSec>" << system_page_faults_per_sec << "</PageFaultsPerSec>\n";
        oss << "    <PagesInputPerSec>" << system_pages_input_per_sec << "</PagesInputPerSec>\n";
        oss << "    <PagesOutputPerSec>" << system_pages_output_per_sec << "</PagesOutputPerSec>\n";
        oss << "    <CompressedPagesTotal>" << system_compressed_pages_total << "</CompressedPagesTotal>\n";
        oss << "  </SystemMetrics>\n";
        oss << "  <DerivedMaps>\n";
        // Ensure these members are actually populated or handled if empty
        oss << "    <EntropyMap>" << vec_to_str(entropy_map_derived) << "</EntropyMap>\n";
        oss << "    <VolatilityMap>" << vec_to_str(volatility_map_derived) << "</VolatilityMap>\n";
        oss << "  </DerivedMaps>\n";
        oss << "  <AccessHeatmap>\n";
        for (const auto& hotspot : process_memory_hotspots) { // 'const auto&' and proper loop
            oss << "    <Process HotspotName=\"" << hotspot.first << "\" Metric=\"" << hotspot.second << "\"/>\n";
        }
        oss << "  </AccessHeatmap>\n";
        oss << "</VirtualMemorySnapshot>\n";
        return oss.str();
    }


    // --- Constructor / Destructor ---
    QuectoVirtualMemoryCollector::QuectoVirtualMemoryCollector(const std::string& log_dir, const std::string& monitored_dir)
        : log_directory_(log_dir), phQuery_(NULL),
        monitored_code_directory_(monitored_dir) // Use the path passed from main.cpp
    {
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
        // Start new thread for file system monitoring
        file_system_collector_thread_ = std::thread(&QuectoVirtualMemoryCollector::file_system_collector_loop, this);
    }

    void QuectoVirtualMemoryCollector::stop_collection() {
        if (!running_) {
            std::cerr << "Collection not running." << std::endl;
            return;
        }
        running_ = false; // Signal threads to stop
        if (edge_collector_thread_.joinable()) edge_collector_thread_.join();
        if (snapshot_collector_thread_.joinable()) snapshot_collector_thread_.join();
        if (file_system_collector_thread_.joinable()) file_system_collector_thread_.join();
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

        // Corrected PDH counter paths:
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
            // Ensure snapshot members are initialized even on error to prevent undefined behavior
            snapshot.system_commit_bytes_total = 0;
            snapshot.system_available_bytes = 0;
            snapshot.system_page_faults_per_sec = 0;
            snapshot.system_pages_input_per_sec = 0;
            snapshot.system_pages_output_per_sec = 0;
            snapshot.system_compressed_pages_total = 0;
            // Also ensure derived vectors are not accessed if not populated
            snapshot.entropy_map_derived.clear();
            snapshot.volatility_map_derived.clear();
            snapshot.process_memory_hotspots.clear();
            return;
        }

        // Retrieve counter values only if the counter handle is valid
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
            return hotspots;
        }

        cProcesses = cbNeeded / sizeof(DWORD);
        for (unsigned int i = 0; i < cProcesses; i++) {
            if (aProcesses[i] == 0) continue;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
            if (hProcess == NULL) continue;

            TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
            HMODULE hMod;
            DWORD cb;
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cb)) {
                GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
            }

            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
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

    // --- Collector Loops (with real data acquisition) ---
    void QuectoVirtualMemoryCollector::snapshot_collector_loop() {
        while (running_) {
            VirtualMemorySnapshot snapshot; // Correct instantiation
            snapshot.timestamp = std::chrono::system_clock::now();

            // Populate derived maps with placeholder data for now if they are not computed elsewhere
            // For example:
            snapshot.entropy_map_derived = { 0.1, 0.2, 0.3 };
            snapshot.volatility_map_derived = { 0.01, 0.02 };

            QueryPdhCounters(snapshot);
            snapshot.process_memory_hotspots = get_process_memory_hotspots();

            // Add debug output for snapshot values
            std::cout << "Snapshot collected (timestamp: "
                << std::chrono::duration_cast<std::chrono::seconds>(snapshot.timestamp.time_since_epoch()).count()
                << "), Commit Bytes: " << snapshot.system_commit_bytes_total
                << ", Available Bytes: " << snapshot.system_available_bytes
                << ", Page Faults/sec: " << snapshot.system_page_faults_per_sec
                << ", Hotspots Count: " << snapshot.process_memory_hotspots.size()
                << std::endl;

            on_snapshot_captured(snapshot);
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }

    void QuectoVirtualMemoryCollector::edge_collector_loop() {
        std::map<DWORD, std::string> known_processes;

        while (running_) {
            DWORD aProcesses[1024], cbNeeded, cProcesses;
            if (EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
                cProcesses = cbNeeded / sizeof(DWORD);
                std::map<DWORD, std::string> current_processes;
                for (unsigned int i = 0; i < cProcesses; i++) {
                    if (aProcesses[i] == 0) continue;
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
                    if (hProcess) {
                        TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
                        HMODULE hMod;
                        DWORD cb;
                        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cb)) {
                            GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
                        }
                        current_processes[aProcesses[i]] = ConvertWCharToString(szProcessName);
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
                        edge.quecto_coupling_matrix = { {1.0, 0.0}, {0.0, 0.0} };
                        on_qvm_edge_captured(edge);
                        std::cout << "Edge captured: Process '" << pair.second << "' (ID: " << pair.first << ") started." << std::endl;
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
                        edge.quecto_coupling_matrix = { {0.0, 1.0}, {0.0, 0.0} };
                        on_qvm_edge_captured(edge);
                        std::cout << "Edge captured: Process '" << pair.second << "' (ID: " << pair.first << ") stopped." << std::endl;
                    }
                }
                known_processes = current_processes;
            }
            else {
                std::cerr << "ERROR: EnumProcesses failed in edge_collector_loop." << std::endl;
            }

            // This block ensures at least one edge is always logged if no processes are detected
            // (Even if EnumProcesses works, this provides a baseline of output)
            QVMEdge edge;
            edge.source_node_id = "vm_001";
            edge.target_node_id = "page_42";
            edge.timestamp = std::chrono::system_clock::now();
            edge.quecto_coupling_matrix = { {0.0001, 0.0002}, {0.0003, 0.0004} };
            edge.context_tags = { "paging_sim", "compression_sim" };
            on_qvm_edge_captured(edge);
            std::cout << "Edge captured: Synthetic VM interaction (known_processes empty)." << std::endl;

            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }


    // --- File System Monitoring Loop ---
    void QuectoVirtualMemoryCollector::file_system_collector_loop() {
        if (monitored_code_directory_.empty()) {
            std::cerr << "File system collector: monitored_code_directory_ is not set. Please provide a valid path." << std::endl;
            return;
        }
        std::cout << "File system collector: Attempting to monitor directory: " << monitored_code_directory_ << std::endl;

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
            // Use WideChar output for WCHAR strings
            std::wcerr << L"File system collector: CreateFileW failed for directory \""
                << w_monitored_code_directory << L"\" with error " << error << std::endl;
            return; // Return if directory cannot be opened
        }
        else {
            std::cout << "File system collector: Successfully opened directory handle." << std::endl;
        }

        const DWORD BUFFER_SIZE = 4096;
        alignas(FILE_NOTIFY_INFORMATION) BYTE buffer[BUFFER_SIZE];
        DWORD bytes_returned;
        OVERLAPPED overlapped;
        ZeroMemory(&overlapped, sizeof(overlapped));

        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (overlapped.hEvent == NULL) {
            std::cerr << "File system collector: CreateEvent failed." << std::endl;
            CloseHandle(hDir);
            return;
        }
        else {
            std::cout << "File system collector: Event handle created." << std::endl;
        }

        // Initial ReadDirectoryChangesW call
        std::cout << "File system collector: Issuing initial ReadDirectoryChangesW." << std::endl;
        BOOL result = ReadDirectoryChangesW(
            hDir,
            buffer,
            BUFFER_SIZE,
            TRUE, // bWatchSubtree = TRUE for recursive monitoring
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytes_returned,
            &overlapped,
            NULL
        );

        if (result == 0 && GetLastError() != ERROR_IO_PENDING) {
            DWORD error = GetLastError();
            std::cerr << "File system collector: Initial ReadDirectoryChangesW failed with error " << error << std::endl;
            CloseHandle(overlapped.hEvent);
            CloseHandle(hDir);
            return;
        }
        else if (result == 0 && GetLastError() == ERROR_IO_PENDING) {
            std::cout << "File system collector: Initial ReadDirectoryChangesW pending (normal for async operation)." << std::endl;
        }
        else { // Should not happen with OVERLAPPED, but for completeness
            std::cout << "File system collector: Initial ReadDirectoryChangesW completed synchronously (unexpected for OVERLAPPED)." << std::endl;
        }


        while (running_) {
            std::cout << "File system collector: Waiting for directory changes..." << std::endl;
            DWORD wait_status = WaitForSingleObject(overlapped.hEvent, INFINITE);

            if (wait_status == WAIT_OBJECT_0) {
                std::cout << "File system collector: Change detected (event signaled)." << std::endl;
                if (GetOverlappedResult(hDir, &overlapped, &bytes_returned, FALSE)) {
                    if (bytes_returned > 0) {
                        FILE_NOTIFY_INFORMATION* pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);
                        while (true) {
                            std::string filename = ConvertWCharToString(pNotify->FileName);
                            std::string full_path = monitored_code_directory_ + "\\" + filename;

                            std::cout << "File system collector: Detected change - File: " << filename
                                << ", Action: " << pNotify->Action << std::endl;

                            // ... rest of your existing logic for handling file changes ...
                            std::string action_type;
                            std::vector<std::string> context_tags;

                            switch (pNotify->Action) {
                            case FILE_ACTION_ADDED:           action_type = "ADDED"; context_tags.push_back("file_create"); break;
                            case FILE_ACTION_REMOVED:         action_type = "REMOVED"; context_tags.push_back("file_delete"); break;
                            case FILE_ACTION_MODIFIED:        action_type = "MODIFIED"; context_tags.push_back("file_edit"); break;
                            case FILE_ACTION_RENAMED_OLD_NAME: action_type = "RENAMED_OLD"; context_tags.push_back("file_rename"); break;
                            case FILE_ACTION_RENAMED_NEW_NAME: action_type = "RENAMED_NEW"; context_tags.push_back("file_rename"); break;
                            default:                          action_type = "UNKNOWN"; break;
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

                            QVMEdge file_edge;
                            file_edge.timestamp = std::chrono::system_clock::now();
                            file_edge.source_node_id = "USER_CADEL_ANDERSON";
                            file_edge.target_node_id = full_path;
                            file_edge.context_tags = context_tags;

                            file_edge.quecto_coupling_matrix = {
                                {1.0, 0.0, 0.0},
                                {0.0, 1.0, 0.0},
                                {0.0, 0.0, 1.0}
                            };

                            if (action_type == "MODIFIED") {
                                file_edge.quecto_coupling_matrix[0][0] = 0.8;
                                file_edge.quecto_coupling_matrix[1][1] = 0.5;
                            }
                            else if (action_type == "ADDED" || action_type == "REMOVED") {
                                file_edge.quecto_coupling_matrix[0][0] = 1.0;
                            }

                            this->on_qvm_edge_captured(file_edge);
                            // End of your existing logic for handling file changes

                            if (pNotify->NextEntryOffset == 0) break;
                            pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>((BYTE*)pNotify + pNotify->NextEntryOffset);
                        }
                    }
                    else {
                        std::cout << "File system collector: GetOverlappedResult returned 0 bytes, no changes processed." << std::endl;
                    }
                    ResetEvent(overlapped.hEvent);

                    result = ReadDirectoryChangesW(
                        hDir,
                        buffer,
                        BUFFER_SIZE,
                        TRUE,
                        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                        FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                        &bytes_returned,
                        &overlapped,
                        NULL
                    );

                    if (result == 0 && GetLastError() != ERROR_IO_PENDING) {
                        DWORD error = GetLastError();
                        std::cerr << "File system collector: Reissuing ReadDirectoryChangesW failed with error " << error << std::endl;
                        break;
                    }
                    else if (result == 0 && GetLastError() == ERROR_IO_PENDING) {
                        std::cout << "File system collector: ReadDirectoryChangesW reissued and pending." << std::endl;
                    }
                    else { // Should not happen with OVERLAPPED
                        std::cout << "File system collector: ReadDirectoryChangesW reissued and completed synchronously." << std::endl;
                    }

                }
                else {
                    DWORD error = GetLastError();
                    std::cerr << "File system collector: GetOverlappedResult failed with error " << error << std::endl;
                    break;
                }
            }
        }

        CloseHandle(overlapped.hEvent);
        CloseHandle(hDir);
        std::cout << "File system collector stopped." << std::endl;
    }

} // namespace QVMC