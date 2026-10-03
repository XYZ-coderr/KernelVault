/**
 * @file main.cpp
 * @brief Command-line interface entry point for kvault.
 *
 * Implements CLI argument parsing, vault command routing, and output formatting.
 */

#include "VaultManager.hpp"
#include "Logger.hpp"

#include <iostream>
#include <string>
#include <string_view>

namespace {

void printBanner() {
    std::cout << "\033[1;36m"
              << "===============================================================\n"
              << "  KVAULT: High-Assurance Linux Kernel-Assisted Secure Storage  \n"
              << "===============================================================\n"
              << "\033[0m";
}

void printUsage(const char* prog) {
    std::cout << "Usage:\n"
              << "  " << prog << " init    --vault <path>\n"
              << "  " << prog << " encrypt --in <file> --vault <path> --key <passphrase>\n"
              << "  " << prog << " decrypt --file <filename> --vault <path> --out <dest> --key <passphrase>\n"
              << "  " << prog << " status  --vault <path>\n\n"
              << "Options:\n"
              << "  --verbose, -v   Enable verbose debug logging\n"
              << "  --help, -h      Display this help dialog\n";
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printBanner();
        printUsage(argv[0]);
        return 1;
    }

    std::string command = argv[1];
    if (command == "--help" || command == "-h") {
        printBanner();
        printUsage(argv[0]);
        return 0;
    }

    std::string vaultPath;
    std::string inputFile;
    std::string fileRecord;
    std::string outputFile;
    std::string key;
    bool verbose = false;

    for (int i = 2; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--vault" && i + 1 < argc) {
            vaultPath = argv[++i];
        } else if (arg == "--in" && i + 1 < argc) {
            inputFile = argv[++i];
        } else if (arg == "--file" && i + 1 < argc) {
            fileRecord = argv[++i];
        } else if (arg == "--out" && i + 1 < argc) {
            outputFile = argv[++i];
        } else if (arg == "--key" && i + 1 < argc) {
            key = argv[++i];
        } else if (arg == "--verbose" || arg == "-v") {
            verbose = true;
        }
    }

    if (verbose) {
        kvault::Logger::setMinLevel(kvault::Logger::Level::Debug);
    }

    if (vaultPath.empty()) {
        kvault::Logger::error("Missing required parameter: --vault <path>");
        return 1;
    }

    kvault::VaultManager vault(vaultPath);

    int exitCode = 0;

    if (command == "init") {
        printBanner();
        if (!vault.initializeVault()) {
            exitCode = 1;
        }
    } else if (command == "encrypt") {
        printBanner();
        if (inputFile.empty()) {
            kvault::Logger::error("Missing required parameter: --in <file>");
            exitCode = 1;
        } else if (key.empty()) {
            kvault::Logger::error("Missing required parameter: --key <passphrase>");
            exitCode = 1;
        } else {
            if (!vault.encryptFile(inputFile, key)) {
                exitCode = 1;
            }
        }
    } else if (command == "decrypt") {
        printBanner();
        if (fileRecord.empty()) {
            kvault::Logger::error("Missing required parameter: --file <filename>");
            exitCode = 1;
        } else if (outputFile.empty()) {
            kvault::Logger::error("Missing required parameter: --out <destination>");
            exitCode = 1;
        } else if (key.empty()) {
            kvault::Logger::error("Missing required parameter: --key <passphrase>");
            exitCode = 1;
        } else {
            if (!vault.decryptFile(fileRecord, outputFile, key)) {
                exitCode = 1;
            }
        }
    } else if (command == "status") {
        printBanner();
        auto status = vault.inspectStatus();
        std::cout << "\nVault Diagnostics for: " << status.vault_path << "\n";
        std::cout << "  - Initialized:              " << (status.is_initialized ? "YES" : "NO") << "\n";
        std::cout << "  - Stored Records:           " << status.file_count << "\n";
        std::cout << "  - Total Encrypted Size:     " << status.total_vault_bytes << " bytes\n";
        std::cout << "  - Kernel Driver Node:       "
                  << (status.kernel_driver_available ? "\033[32mACTIVE (/dev/kvault)\033[0m" : "\033[33mINACTIVE (Software Fallback)\033[0m")
                  << "\n";

        if (status.kernel_driver_available) {
            std::cout << "  - Driver Protocol Version:  0x" << std::hex << status.kernel_driver_version << std::dec << "\n";
            std::cout << "  - Lifetime Transformed:     " << status.kernel_bytes_transformed << " bytes\n";
        }

        if (!status.stored_files.empty()) {
            std::cout << "\nFiles in Vault:\n";
            for (const auto& f : status.stored_files) {
                std::cout << "    [+] " << f << "\n";
            }
        }
        std::cout << "\n";
    } else {
        kvault::Logger::error("Unknown command: " + command);
        printUsage(argv[0]);
        exitCode = 1;
    }

    // Zero out sensitive command-line key material in process memory before exiting
    if (!key.empty()) {
        kvault::KeyDerivation::secureZero(key.data(), key.size());
    }

    return exitCode;
}
