# QuectoVirtualMemoryCollector (QVMC)

**Author:** Cadell Richard Anderson  
**License:** Custom License: Quectobyte Attribution License (QAL) v1.0
**Version:** 0.1  
**Date:** July 2025

// main.cpp
#define NOMINMAX // Prevents Windows.h from defining min/max macros
#include <iostream>
#include "qvmc_collector.h"
#include <string>
#include <limits>

int main() {
    std::cout << "Starting Quecto Virtual Memory Collector application..." << std::endl;

    std::string log_directory = "data/logs"; // Default logs directory
    // Define the monitored code directory here
    std::string code_directory_to_monitor = "C:\\Users\\Noob\\"; // <<< SET THIS TO YOUR ACTUAL PROJECT PATH

    // Pass both arguments to the constructor
    QVMC::QuectoVirtualMemoryCollector collector(log_directory, code_directory_to_monitor);

    try {
        collector.start_collection();
        std::cout << "Collection started. Press Enter to stop." << std::endl;

        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();

        collector.stop_collection();
        std::cout << "Collection stopped. Exiting." << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        return 1;
    }
    catch (...) {
        std::cerr << "An unknown error occurred." << std::endl;
        return 1;
    }

    return 0;
}
