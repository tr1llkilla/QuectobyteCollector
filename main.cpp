# QuectoVirtualMemoryCollector (QVMC)

**Author:** Cadell Richard Anderson  
**License:** Custom License: Quectobyte Attribution License (QAL) v1.0
**Version:** 0.1  
**Date:** July 2025

// main.cpp
#include "qvmc_collector.h"
#include <iostream>
#include <string>
#include <filesystem>
#include <windows.h> // For SetConsoleOutputCP

int main() {
    // Set console output to UTF-8 for proper display of wide characters
    SetConsoleOutputCP(CP_UTF8);
    std::ios::sync_with_stdio(false); // Untie C++ streams from C stdio for performance

    std::cout << "Starting Transcendental Virtual Memory Observer..." << std::endl;

    std::string log_directory = "qvm_logs";
    // !!! IMPORTANT: CHANGE THIS PATH !!!
    // This should be a directory where you actively modify code files for the file system monitor
    // and where the scanner will periodically check files.
    std::string monitored_code_directory = "C:\\"; // Example: create this folder and put some .cpp files in it

    // Ensure the log directory exists
    std::filesystem::create_directories(log_directory);
    // Ensure the monitored directory exists (the program will create the quarantine folder)
    std::filesystem::create_directories(monitored_code_directory);

    // Initialize the collector with the log and monitored directories
    QVMC::QuectoVirtualMemoryCollector collector(log_directory, monitored_code_directory);

    // Start all collection threads
    collector.start_collection();

    std::cout << "Collection started. Check 'qvm_logs' folder for XML output." << std::endl;
    std::cout << "Modify files in '" << monitored_code_directory << "' to see real-time file system events." << std::endl;
    std::cout << "New: A background scanner will periodically check files in this directory for suspiciousness." << std::endl;
    std::cout << "Files deemed suspicious will be copied to C:\\Users\\Noob\\OneDrive\\Desktop\\Desktop\\ScanSuspisciousResults\\bigscan1 (or your configured path)." << std::endl;
    std::cout << "Press Enter to stop the collector..." << std::endl;
    std::cin.get(); // Wait for user input to stop

    // Stop all collection threads
    collector.stop_collection();
    std::cout << "Collection stopped. Data logged to " << log_directory << std::endl;

    return 0;
}
