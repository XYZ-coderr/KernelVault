/**
 * @file VaultManager.hpp
 * @brief High-level vault header, chunking, locking, and storage orchestration for kvault.
 */

#ifndef VAULT_MANAGER_HPP
#define VAULT_MANAGER_HPP

#include "UniqueFd.hpp"
#include "FileLock.hpp"
#include "AtomicFileWriter.hpp"
#include "KeyDerivation.hpp"
#include "kvault_ioctl.h"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <memory>

namespace kvault {

#pragma pack(push, 1)
/**
 * @struct VaultHeader
 * @brief 96-byte authenticated binary header prepended to every encrypted vault file.
 */
struct VaultHeader {
    uint32_t magic;          /**< Constant magic identifier 'KVLT' (0x4B564C54) */
    uint32_t version;        /**< Format version (0x00000001) */
    uint8_t  salt[16];       /**< Cryptographic salt for PBKDF2 */
    uint8_t  iv[16];         /**< AES-256-CBC Initialization Vector */
    uint64_t original_size;  /**< Unpadded plaintext size in bytes */
    uint64_t payload_size;   /**< Total encrypted payload size in bytes */
    uint8_t  hmac[32];       /**< SHA-256 HMAC authentication tag */
    uint8_t  reserved[8];    /**< Reserved alignment bytes */
};
#pragma pack(pop)

static_assert(sizeof(VaultHeader) == 96, "VaultHeader must be exactly 96 bytes");

/**
 * @struct VaultStatus
 * @brief Information structure for vault health and metrics.
 */
struct VaultStatus {
    bool is_initialized{false};
    std::filesystem::path vault_path;
    size_t file_count{0};
    uint64_t total_vault_bytes{0};
    bool kernel_driver_available{false};
    uint32_t kernel_driver_version{0};
    uint64_t kernel_bytes_transformed{0};
    std::vector<std::string> stored_files;
};

/**
 * @class VaultManager
 * @brief Core orchestrator for secure file storage, encryption, and decryption.
 */
class VaultManager {
public:
    static constexpr uint32_t VAULT_MAGIC = 0x4B564C54; // "KVLT"
    static constexpr uint32_t LEGACY_MAGIC = 0x53454356; // "SECV"
    static constexpr uint32_t VAULT_VERSION = 1;
    static constexpr size_t CHUNK_SIZE = 64 * 1024; // 64 KiB streaming chunks

    /**
     * @brief Constructs a VaultManager managing the specified vault directory.
     * @param vaultPath Directory path to vault.
     */
    explicit VaultManager(std::filesystem::path vaultPath);

    /**
     * @brief Destructor. Ensures device and locks are released cleanly.
     */
    ~VaultManager() noexcept;

    // Non-copyable
    VaultManager(const VaultManager&) = delete;
    VaultManager& operator=(const VaultManager&) = delete;
    VaultManager(VaultManager&&) noexcept = default;
    VaultManager& operator=(VaultManager&&) noexcept = default;

    /**
     * @brief Initializes a new secure vault directory with 0700 permissions and metadata.
     * @return True on success, false if already initialized or permissions fail.
     */
    bool initializeVault();

    /**
     * @brief Encrypts a source file and stores it atomically inside the vault.
     * @param srcFile Path to plaintext source file.
     * @param passphrase User passphrase for key derivation.
     * @return True on success, false otherwise.
     */
    bool encryptFile(const std::filesystem::path& srcFile, std::string_view passphrase);

    /**
     * @brief Decrypts a vault record and restores it to the destination file.
     * @param filename Base filename of file stored in vault.
     * @param destFile Target path to write recovered plaintext.
     * @param passphrase User passphrase for key derivation.
     * @return True on success, false if authentication or decryption fails.
     */
    bool decryptFile(const std::string& filename,
                     const std::filesystem::path& destFile,
                     std::string_view passphrase);

    /**
     * @brief Inspects vault statistics, active locks, and kernel accelerator health.
     * @return VaultStatus structure with diagnostic details.
     */
    [[nodiscard]] VaultStatus inspectStatus();

    /**
     * @brief Checks if the kernel acceleration driver /dev/kvault is available.
     */
    [[nodiscard]] bool isKernelDriverLoaded() const;

private:
    std::filesystem::path m_vaultPath;
    std::filesystem::path m_recordsPath;
    std::filesystem::path m_locksPath;
    std::filesystem::path m_metaPath;

    UniqueFd openKernelDevice();
    bool configureKernelSession(int devFd,
                                std::span<const uint8_t, 32> key,
                                std::span<const uint8_t, 16> iv,
                                int mode);
    void flushKernelSession(int devFd);

    // Cryptographic transformation engine: uses kernel device if fd >= 0, or fallback
    bool transformBuffer(int devFd,
                         std::span<const uint8_t> input,
                         std::vector<uint8_t>& output,
                         std::span<const uint8_t, 32> key,
                         std::span<uint8_t, 16> iv,
                         bool encrypt);

    std::filesystem::path getLockFilePath(const std::string& filename) const;
    std::filesystem::path getRecordFilePath(const std::string& filename) const;
};

} // namespace kvault

namespace secstore = kvault;

#endif // VAULT_MANAGER_HPP
