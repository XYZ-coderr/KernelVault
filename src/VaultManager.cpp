/**
 * @file VaultManager.cpp
 * @brief Implementation of VaultManager orchestration and cryptographic streaming for kvault.
 */

#include "VaultManager.hpp"
#include "Logger.hpp"

#include <fstream>
#include <sstream>
#include <cstring>
#include <array>
#include <algorithm>
#include <limits>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

namespace kvault {

namespace {

// ============================================================================
// Internal Standalone AES-256 Engine for User-Space Fallback / Mock Mode
// ============================================================================

class SoftwareAes256 {
public:
    static constexpr size_t BLOCK_SIZE = 16;
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t ROUND_KEYS_SIZE = 240; // (14 + 1) * 16

    static void expandKey(std::span<const uint8_t, 32> key, uint8_t* roundKeys) noexcept {
        static const uint8_t rcon[15] = {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1b, 0x36, 0x00, 0x00, 0x00, 0x00
        };

        std::memcpy(roundKeys, key.data(), 32);

        uint32_t temp = 0;
        size_t bytesGenerated = 32;
        size_t rconIter = 1;

        while (bytesGenerated < ROUND_KEYS_SIZE) {
            temp = (static_cast<uint32_t>(roundKeys[bytesGenerated - 4]) << 24) |
                   (static_cast<uint32_t>(roundKeys[bytesGenerated - 3]) << 16) |
                   (static_cast<uint32_t>(roundKeys[bytesGenerated - 2]) << 8)  |
                   (static_cast<uint32_t>(roundKeys[bytesGenerated - 1]));

            if (bytesGenerated % 32 == 0) {
                // RotWord & SubWord
                temp = (temp << 8) | (temp >> 24);
                temp = subWord(temp) ^ (static_cast<uint32_t>(rcon[rconIter++]) << 24);
            } else if (bytesGenerated % 32 == 16) {
                temp = subWord(temp);
            }

            uint32_t prev = (static_cast<uint32_t>(roundKeys[bytesGenerated - 32]) << 24) |
                            (static_cast<uint32_t>(roundKeys[bytesGenerated - 31]) << 16) |
                            (static_cast<uint32_t>(roundKeys[bytesGenerated - 30]) << 8)  |
                            (static_cast<uint32_t>(roundKeys[bytesGenerated - 29]));

            uint32_t result = prev ^ temp;
            roundKeys[bytesGenerated + 0] = static_cast<uint8_t>((result >> 24) & 0xFF);
            roundKeys[bytesGenerated + 1] = static_cast<uint8_t>((result >> 16) & 0xFF);
            roundKeys[bytesGenerated + 2] = static_cast<uint8_t>((result >> 8) & 0xFF);
            roundKeys[bytesGenerated + 3] = static_cast<uint8_t>(result & 0xFF);

            bytesGenerated += 4;
        }
    }

    static void encryptBlock(const uint8_t* in, uint8_t* out, const uint8_t* roundKeys) noexcept {
        uint8_t state[16];
        std::memcpy(state, in, 16);

        addRoundKey(state, roundKeys);

        for (int round = 1; round < 14; ++round) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys + round * 16);
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys + 14 * 16);

        std::memcpy(out, state, 16);
        KeyDerivation::secureZero(state, sizeof(state));
    }

    static void decryptBlock(const uint8_t* in, uint8_t* out, const uint8_t* roundKeys) noexcept {
        uint8_t state[16];
        std::memcpy(state, in, 16);

        addRoundKey(state, roundKeys + 14 * 16);

        for (int round = 13; round >= 1; --round) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, roundKeys + round * 16);
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, roundKeys);

        std::memcpy(out, state, 16);
        KeyDerivation::secureZero(state, sizeof(state));
    }

private:
    static const uint8_t sbox[256];
    static const uint8_t rsbox[256];

    static uint32_t subWord(uint32_t word) noexcept {
        return (static_cast<uint32_t>(sbox[(word >> 24) & 0xFF]) << 24) |
               (static_cast<uint32_t>(sbox[(word >> 16) & 0xFF]) << 16) |
               (static_cast<uint32_t>(sbox[(word >> 8) & 0xFF]) << 8)   |
               (static_cast<uint32_t>(sbox[word & 0xFF]));
    }

    static void addRoundKey(uint8_t* state, const uint8_t* key) noexcept {
        for (int i = 0; i < 16; ++i) state[i] ^= key[i];
    }

    static void subBytes(uint8_t* state) noexcept {
        for (int i = 0; i < 16; ++i) state[i] = sbox[state[i]];
    }

    static void invSubBytes(uint8_t* state) noexcept {
        for (int i = 0; i < 16; ++i) state[i] = rsbox[state[i]];
    }

    static void shiftRows(uint8_t* state) noexcept {
        uint8_t temp[16];
        temp[0] = state[0];   temp[1] = state[5];   temp[2] = state[10];  temp[3] = state[15];
        temp[4] = state[4];   temp[5] = state[9];   temp[6] = state[14];  temp[7] = state[3];
        temp[8] = state[8];   temp[9] = state[13];  temp[10] = state[2];  temp[11] = state[7];
        temp[12] = state[12]; temp[13] = state[1];  temp[14] = state[6];  temp[15] = state[11];
        std::memcpy(state, temp, 16);
    }

    static void invShiftRows(uint8_t* state) noexcept {
        uint8_t temp[16];
        temp[0] = state[0];   temp[1] = state[13];  temp[2] = state[10];  temp[3] = state[7];
        temp[4] = state[4];   temp[5] = state[1];   temp[6] = state[14];  temp[7] = state[11];
        temp[8] = state[8];   temp[9] = state[5];   temp[10] = state[2];  temp[11] = state[15];
        temp[12] = state[12]; temp[13] = state[9];  temp[14] = state[6];  temp[15] = state[3];
        std::memcpy(state, temp, 16);
    }

    static uint8_t xtime(uint8_t x) noexcept {
        return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
    }

    static uint8_t multiply(uint8_t x, uint8_t y) noexcept {
        return (((y & 1) * x) ^
                ((y >> 1 & 1) * xtime(x)) ^
                ((y >> 2 & 1) * xtime(xtime(x))) ^
                ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
                ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
    }

    static void mixColumns(uint8_t* state) noexcept {
        for (int i = 0; i < 4; ++i) {
            uint8_t* c = state + i * 4;
            uint8_t a = c[0], b = c[1], d = c[2], e = c[3];
            c[0] = xtime(a) ^ (b ^ xtime(b)) ^ d ^ e;
            c[1] = a ^ xtime(b) ^ (d ^ xtime(d)) ^ e;
            c[2] = a ^ b ^ xtime(d) ^ (e ^ xtime(e));
            c[3] = (a ^ xtime(a)) ^ b ^ d ^ xtime(e);
        }
    }

    static void invMixColumns(uint8_t* state) noexcept {
        for (int i = 0; i < 4; ++i) {
            uint8_t* c = state + i * 4;
            uint8_t a = c[0], b = c[1], d = c[2], e = c[3];
            c[0] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(d, 0x0d) ^ multiply(e, 0x09);
            c[1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(d, 0x0b) ^ multiply(e, 0x0d);
            c[2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(d, 0x0e) ^ multiply(e, 0x0b);
            c[3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(d, 0x09) ^ multiply(e, 0x0e);
        }
    }
};

const uint8_t SoftwareAes256::sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t SoftwareAes256::rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

} // namespace

// ============================================================================
// VaultManager Implementation
// ============================================================================

VaultManager::VaultManager(std::filesystem::path vaultPath)
    : m_vaultPath(std::move(vaultPath)) {
    m_recordsPath = m_vaultPath / "records";
    m_locksPath = m_vaultPath / "locks";
    m_metaPath = m_vaultPath / "vault.meta";
}

VaultManager::~VaultManager() noexcept = default;

bool VaultManager::initializeVault() {
    std::error_code ec;

    if (std::filesystem::exists(m_metaPath)) {
        Logger::error("Vault already initialized at: " + m_vaultPath.string());
        return false;
    }

    // Create directories
    std::filesystem::create_directories(m_recordsPath, ec);
    std::filesystem::create_directories(m_locksPath, ec);

    if (ec) {
        Logger::error("Failed to create vault directories: " + ec.message());
        return false;
    }

    // Generate Master Salt
    std::array<uint8_t, 16> masterSalt{};
    if (!KeyDerivation::generateSalt(masterSalt)) {
        Logger::error("Operating system entropy source failed while initializing the vault");
        return false;
    }

    // Write vault.meta manifest
    AtomicFileWriter metaWriter(m_metaPath, false);
    if (!metaWriter.open()) {
        Logger::error("Failed to open vault metadata file for writing.");
        return false;
    }

    std::string metaContent = "KVLT01\n";
    metaContent += "version=1\n";
    metaContent += "kdf=PBKDF2-HMAC-SHA256\n";
    metaContent += "rounds=100000\n";
    metaContent += "salt=";
    for (uint8_t b : masterSalt) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        metaContent += buf;
    }
    metaContent += "\n";

    std::span<const uint8_t> spanData(reinterpret_cast<const uint8_t*>(metaContent.data()), metaContent.size());
    if (!metaWriter.write(spanData) || !metaWriter.commit()) {
        Logger::error("Failed to atomically commit vault.meta");
        return false;
    }

    Logger::info("Initialized secure vault at: " + m_vaultPath.string());
    return true;
}

UniqueFd VaultManager::openKernelDevice() {
    int fd = ::open("/dev/kvault", O_RDWR);
    if (fd >= 0) {
        Logger::kernel("Opened Linux driver device /dev/kvault");
        return UniqueFd(fd);
    }
    return UniqueFd(-1);
}

bool VaultManager::configureKernelSession(int devFd,
                                         std::span<const uint8_t, 32> key,
                                         std::span<const uint8_t, 16> iv,
                                         int mode) {
    if (devFd < 0) return false;

    // 1. Set mode
    if (::ioctl(devFd, KVAULT_IOCTL_SET_MODE, &mode) != 0) {
        return false;
    }

    // 2. Set key
    struct kvault_key_param key_param{};
    std::memcpy(key_param.key, key.data(), 32);
    key_param.key_len = 32;
    if (::ioctl(devFd, KVAULT_IOCTL_SET_KEY, &key_param) != 0) {
        KeyDerivation::secureZero(&key_param, sizeof(key_param));
        return false;
    }
    KeyDerivation::secureZero(&key_param, sizeof(key_param));

    // 3. Set IV
    struct kvault_iv_param iv_param{};
    std::memcpy(iv_param.iv, iv.data(), 16);
    iv_param.iv_len = 16;
    if (::ioctl(devFd, KVAULT_IOCTL_SET_IV, &iv_param) != 0) {
        return false;
    }

    return true;
}

void VaultManager::flushKernelSession(int devFd) {
    if (devFd >= 0) {
        ::ioctl(devFd, KVAULT_IOCTL_FLUSH_KEY);
        Logger::kernel("Dispatched KVAULT_IOCTL_FLUSH_KEY to wipe in-kernel key memory");
    }
}

bool VaultManager::transformBuffer(int devFd,
                                  std::span<const uint8_t> input,
                                  std::vector<uint8_t>& output,
                                  std::span<const uint8_t, 32> key,
                                  std::span<uint8_t, 16> iv,
                                  bool encrypt) {
    if (input.empty()) {
        output.clear();
        return true;
    }

    if (devFd >= 0) {
        // Kernel acceleration path via IOCTL transform
        output.resize(input.size());
        struct kvault_transform_param trans{};
        trans.src = input.data();
        trans.dst = output.data();
        trans.length = static_cast<uint32_t>(input.size());
        trans.mode = encrypt ? KVAULT_MODE_ENCRYPT : KVAULT_MODE_DECRYPT;

        if (::ioctl(devFd, KVAULT_IOCTL_TRANSFORM, &trans) == 0) {
            return true;
        }
        Logger::warn("Kernel IOCTL transform failed, falling back to software cipher");
    }

    // Fallback: Software AES-256-CBC engine
    output.resize(input.size());
    uint8_t roundKeys[SoftwareAes256::ROUND_KEYS_SIZE];
    SoftwareAes256::expandKey(key, roundKeys);

    uint8_t currentIv[16];
    std::memcpy(currentIv, iv.data(), 16);

    for (size_t offset = 0; offset < input.size(); offset += 16) {
        const uint8_t* inBlock = input.data() + offset;
        uint8_t* outBlock = output.data() + offset;

        if (encrypt) {
            uint8_t xored[16];
            for (int i = 0; i < 16; ++i) {
                xored[i] = inBlock[i] ^ currentIv[i];
            }
            SoftwareAes256::encryptBlock(xored, outBlock, roundKeys);
            std::memcpy(currentIv, outBlock, 16);
            KeyDerivation::secureZero(xored, sizeof(xored));
        } else {
            uint8_t decrypted[16];
            SoftwareAes256::decryptBlock(inBlock, decrypted, roundKeys);
            for (int i = 0; i < 16; ++i) {
                outBlock[i] = decrypted[i] ^ currentIv[i];
            }
            std::memcpy(currentIv, inBlock, 16);
            KeyDerivation::secureZero(decrypted, sizeof(decrypted));
        }
    }

    // Update session IV
    std::memcpy(iv.data(), currentIv, 16);
    KeyDerivation::secureZero(roundKeys, sizeof(roundKeys));
    KeyDerivation::secureZero(currentIv, sizeof(currentIv));

    return true;
}

std::filesystem::path VaultManager::getLockFilePath(const std::string& filename) const {
    return m_locksPath / (filename + ".lock");
}

std::filesystem::path VaultManager::getRecordFilePath(const std::string& filename) const {
    return m_recordsPath / (filename + ".enc");
}

bool VaultManager::encryptFile(const std::filesystem::path& srcFile, std::string_view passphrase) {
    if (!std::filesystem::exists(srcFile)) {
        Logger::error("Source file does not exist: " + srcFile.string());
        return false;
    }

    const std::string filename = srcFile.filename().string();
    const auto lockPath = getLockFilePath(filename);
    const auto destRecordPath = getRecordFilePath(filename);

    // 1. Acquire POSIX advisory write lock (exclusive)
    int lockFdRaw = ::open(lockPath.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);

    UniqueFd lockFd(lockFdRaw);
    if (!lockFd.valid()) {
        Logger::error("Failed to open lock file: " + lockPath.string());
        return false;
    }

    FileLock fileLock(lockFd.get(), FileLock::LockType::Exclusive, FileLock::LockMode::NonBlocking);
    if (!fileLock.isLocked()) {
        Logger::error("Cannot acquire exclusive lock on: " + filename + " (file is currently in use)");
        return false;
    }

    // 2. Generate Salt & IV
    std::array<uint8_t, 16> salt{};
    std::array<uint8_t, 16> iv{};
    if (!KeyDerivation::generateSalt(salt) || !KeyDerivation::generateIv(iv)) {
        Logger::error("Operating system entropy source failed; encryption was not started");
        KeyDerivation::secureZero(salt.data(), salt.size());
        KeyDerivation::secureZero(iv.data(), iv.size());
        return false;
    }

    // 3. Derive 256-bit Key
    std::array<uint8_t, 32> key{};
    if (!KeyDerivation::deriveKeyPbkdf2(passphrase, salt, key)) {
        Logger::error("Key derivation failed");
        return false;
    }

    // 4. Check for Kernel Device Accelerator
    UniqueFd devFd = openKernelDevice();
    bool useKernel = devFd.valid();
    if (useKernel) {
        if (!configureKernelSession(devFd.get(), key, iv, KVAULT_MODE_ENCRYPT)) {
            Logger::warn("Failed to configure kernel crypto session. Reverting to software engine.");
            devFd.reset(-1);
            useKernel = false;
        }
    } else {
        Logger::info("Operating in user-space crypto engine mode (kernel module not active)");
    }

    // 5. Open Input File
    std::ifstream inFile(srcFile, std::ios::binary);
    if (!inFile) {
        Logger::error("Cannot open source file for reading: " + srcFile.string());
        if (useKernel) flushKernelSession(devFd.get());
        KeyDerivation::secureZero(key.data(), sizeof(key));
        return false;
    }

    const uint64_t originalFileSize = std::filesystem::file_size(srcFile);

    // 6. Prepare AtomicFileWriter for Vault Record
    AtomicFileWriter writer(destRecordPath, true);
    if (!writer.open()) {
        Logger::error("Failed to open atomic record destination: " + destRecordPath.string());
        if (useKernel) flushKernelSession(devFd.get());
        KeyDerivation::secureZero(key.data(), sizeof(key));
        return false;
    }

    // Reserve 96 bytes for VaultHeader (written at commit)
    VaultHeader header{};
    header.magic = VAULT_MAGIC;
    header.version = VAULT_VERSION;
    std::memcpy(header.salt, salt.data(), 16);
    std::memcpy(header.iv, iv.data(), 16);
    header.original_size = originalFileSize;

    std::vector<uint8_t> headerPlaceholder(sizeof(VaultHeader), 0);
    if (!writer.write(headerPlaceholder)) {
        Logger::error("Failed to reserve space for the vault record header");
        writer.abort();
        if (useKernel) flushKernelSession(devFd.get());
        KeyDerivation::secureZero(key.data(), sizeof(key));
        return false;
    }

    // 7. Stream and Encrypt File in Chunks
    std::vector<uint8_t> inChunk(CHUNK_SIZE);
    std::vector<uint8_t> encryptedChunk;
    std::vector<uint8_t> fullCiphertext;
    uint64_t totalCipherBytes = 0;

    std::array<uint8_t, 16> runningIv;
    std::memcpy(runningIv.data(), iv.data(), 16);

    while (inFile) {
        inFile.read(reinterpret_cast<char*>(inChunk.data()), CHUNK_SIZE);
        std::streamsize bytesRead = inFile.gcount();
        if (bytesRead <= 0) break;

        // Check if last chunk (apply PKCS#7 padding)
        bool isEof = inFile.peek() == EOF;
        size_t chunkBytes = static_cast<size_t>(bytesRead);

        std::vector<uint8_t> toEncrypt;
        const auto chunkEnd = inChunk.begin() +
                              static_cast<std::vector<uint8_t>::difference_type>(chunkBytes);
        toEncrypt.insert(toEncrypt.end(), inChunk.begin(), chunkEnd);

        if (isEof) {
            size_t padLen = 16 - (chunkBytes % 16);
            for (size_t p = 0; p < padLen; ++p) {
                toEncrypt.push_back(static_cast<uint8_t>(padLen));
            }
        }

        if (!transformBuffer(devFd.get(), toEncrypt, encryptedChunk, key, runningIv, true)) {
            Logger::error("Transform error during chunk encryption");
            writer.abort();
            if (useKernel) flushKernelSession(devFd.get());
            KeyDerivation::secureZero(key.data(), sizeof(key));
            return false;
        }

        if (!writer.write(encryptedChunk)) {
            Logger::error("Failed to write encrypted data to the temporary vault record");
            writer.abort();
            if (useKernel) flushKernelSession(devFd.get());
            KeyDerivation::secureZero(key.data(), sizeof(key));
            return false;
        }
        fullCiphertext.insert(fullCiphertext.end(), encryptedChunk.begin(), encryptedChunk.end());
        totalCipherBytes += encryptedChunk.size();
    }

    if (inFile.bad()) {
        Logger::error("Input file read failed during encryption");
        writer.abort();
        if (useKernel) flushKernelSession(devFd.get());
        KeyDerivation::secureZero(key.data(), sizeof(key));
        return false;
    }

    header.payload_size = totalCipherBytes;

    // 8. Authenticate the complete header (with an empty tag) and ciphertext.
    std::array<uint8_t, 32> computedHmac{};
    const auto headerBytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&header), sizeof(header));
    if (!KeyDerivation::computeHmacSha256(key, headerBytes, fullCiphertext, computedHmac)) {
        Logger::error("Failed to authenticate the encrypted record");
        writer.abort();
        if (useKernel) flushKernelSession(devFd.get());
        KeyDerivation::secureZero(key.data(), sizeof(key));
        KeyDerivation::secureZero(computedHmac.data(), computedHmac.size());
        return false;
    }
    std::memcpy(header.hmac, computedHmac.data(), 32);

    // 9. Commit Atomic Write: rewrite header and flush
    std::fstream tmpStream(writer.getTempPath(), std::ios::in | std::ios::out | std::ios::binary);
    if (!tmpStream) {
        writer.abort();
        Logger::error("Failed to write authenticated header to temp vault file");
        if (useKernel) flushKernelSession(devFd.get());
        KeyDerivation::secureZero(key.data(), sizeof(key));
        return false;
    }
    tmpStream.seekp(0);
    tmpStream.write(reinterpret_cast<const char*>(&header), sizeof(header));
    tmpStream.flush();
    tmpStream.close();

    if (!writer.commit()) {
        Logger::error("Atomic commit failed for encrypted vault record");
        if (useKernel) flushKernelSession(devFd.get());
        KeyDerivation::secureZero(key.data(), sizeof(key));
        return false;
    }

    // 10. Memory Hygiene
    if (useKernel) {
        flushKernelSession(devFd.get());
    }
    KeyDerivation::secureZero(key.data(), sizeof(key));
    KeyDerivation::secureZero(&header, sizeof(header));

    Logger::info("Successfully stored and encrypted into vault: " + filename +
                 " (" + std::to_string(originalFileSize) + " bytes -> " +
                 std::to_string(totalCipherBytes + sizeof(VaultHeader)) + " bytes on disk)");
    return true;
}

bool VaultManager::decryptFile(const std::string& filename,
                              const std::filesystem::path& destFile,
                              std::string_view passphrase) {
    const auto lockPath = getLockFilePath(filename);
    const auto srcRecordPath = getRecordFilePath(filename);

    if (!std::filesystem::exists(srcRecordPath)) {
        Logger::error("Encrypted record not found in vault: " + filename);
        return false;
    }

    // 1. Acquire POSIX advisory read lock (shared)
    int lockFdRaw = ::open(lockPath.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);

    UniqueFd lockFd(lockFdRaw);
    FileLock fileLock;
    if (lockFd.valid()) {
        fileLock.acquire(lockFd.get(), FileLock::LockType::Shared, FileLock::LockMode::Blocking);
    }

    // 2. Read VaultHeader
    std::ifstream recordFile(srcRecordPath, std::ios::binary);
    if (!recordFile) {
        Logger::error("Cannot open vault record for reading: " + srcRecordPath.string());
        return false;
    }

    VaultHeader header{};
    recordFile.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (recordFile.gcount() != sizeof(header)) {
        Logger::error("Corrupted vault record: Incomplete header");
        return false;
    }

    const bool supportedMagic = header.magic == VAULT_MAGIC ||
        (header.magic == LEGACY_MAGIC && header.version == LEGACY_VAULT_VERSION);
    const bool supportedVersion = header.version == VAULT_VERSION ||
        header.version == LEGACY_VAULT_VERSION;
    if (!supportedMagic || !supportedVersion) {
        Logger::error("Invalid vault file magic or incompatible version.");
        return false;
    }

    const uint64_t paddingSize = 16 - (header.original_size % 16);
    const bool payloadLengthOverflow = header.original_size != 0 &&
        header.original_size > std::numeric_limits<uint64_t>::max() - paddingSize;
    const uint64_t expectedPayloadSize = header.original_size == 0
        ? 0
        : (payloadLengthOverflow ? 0 : header.original_size + paddingSize);
    std::error_code fileSizeError;
    const uintmax_t recordFileSize = std::filesystem::file_size(srcRecordPath, fileSizeError);
    const bool recordLengthOverflow = header.payload_size >
        std::numeric_limits<uintmax_t>::max() - sizeof(VaultHeader);
    const uintmax_t expectedRecordSize = recordLengthOverflow
        ? 0
        : sizeof(VaultHeader) + static_cast<uintmax_t>(header.payload_size);
    if (fileSizeError || payloadLengthOverflow || recordLengthOverflow ||
        header.payload_size != expectedPayloadSize ||
        header.original_size > header.payload_size || recordFileSize != expectedRecordSize ||
        header.payload_size > static_cast<uint64_t>(std::numeric_limits<size_t>::max()) ||
        header.payload_size > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        Logger::error("Invalid vault record lengths or trailing data");
        return false;
    }

    // 3. Derive 256-bit Key from Header Salt
    std::span<const uint8_t, 16> saltSpan(header.salt, 16);
    std::array<uint8_t, 32> key{};
    if (!KeyDerivation::deriveKeyPbkdf2(passphrase, saltSpan, key)) {
        Logger::error("Key derivation failed during decryption");
        return false;
    }

    // 4. Verify HMAC-SHA256 authentication tag before transforming
    std::vector<uint8_t> ciphertext(static_cast<size_t>(header.payload_size));
    recordFile.read(reinterpret_cast<char*>(ciphertext.data()), static_cast<std::streamsize>(header.payload_size));
    if (static_cast<uint64_t>(recordFile.gcount()) != header.payload_size) {
        Logger::error("Corrupted vault record: Incomplete payload data");
        KeyDerivation::secureZero(key.data(), sizeof(key));
        return false;
    }

    std::span<const uint8_t, 32> expectedHmac(header.hmac, 32);
    bool authenticated = false;
    if (header.version == LEGACY_VAULT_VERSION) {
        authenticated = KeyDerivation::verifyHmacConstantTime(key, ciphertext, expectedHmac);
    } else {
        VaultHeader authenticatedHeader = header;
        KeyDerivation::secureZero(authenticatedHeader.hmac, sizeof(authenticatedHeader.hmac));
        const auto headerBytes = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(&authenticatedHeader), sizeof(authenticatedHeader));
        authenticated = KeyDerivation::verifyHmacConstantTime(
            key, headerBytes, ciphertext, expectedHmac);
        KeyDerivation::secureZero(&authenticatedHeader, sizeof(authenticatedHeader));
    }
    if (!authenticated) {
        Logger::error("Cryptographic authentication failed: Incorrect passphrase or tampered ciphertext.");
        KeyDerivation::secureZero(key.data(), sizeof(key));
        return false;
    }

    // 5. Check for Kernel Device Accelerator
    UniqueFd devFd = openKernelDevice();
    bool useKernel = devFd.valid();
    std::array<uint8_t, 16> iv;
    std::memcpy(iv.data(), header.iv, 16);

    if (useKernel) {
        if (!configureKernelSession(devFd.get(), key, iv, KVAULT_MODE_DECRYPT)) {
            devFd.reset(-1);
            useKernel = false;
        }
    }

    // 6. Decrypt payload
    std::vector<uint8_t> decrypted;
    if (!transformBuffer(devFd.get(), ciphertext, decrypted, key, iv, false)) {
        Logger::error("Decryption failed during transform");
        if (useKernel) flushKernelSession(devFd.get());
        KeyDerivation::secureZero(key.data(), sizeof(key));
        return false;
    }

    // 7. Remove PKCS#7 padding and validate length
    if (decrypted.size() < header.original_size) {
        Logger::error("Decrypted payload size is less than original file size");
        if (useKernel) flushKernelSession(devFd.get());
        KeyDerivation::secureZero(key.data(), sizeof(key));
        return false;
    }

    decrypted.resize(header.original_size);
    const size_t recoveredSize = decrypted.size();

    // 8. Atomically write recovered file to destination
    AtomicFileWriter writer(destFile, true);
    if (!writer.open() || !writer.write(decrypted) || !writer.commit()) {
        Logger::error("Failed to atomically write recovered file: " + destFile.string());
        if (useKernel) flushKernelSession(devFd.get());
        KeyDerivation::secureZero(key.data(), sizeof(key));
        return false;
    }

    // 9. Memory Hygiene
    if (useKernel) {
        flushKernelSession(devFd.get());
    }
    KeyDerivation::secureZero(key.data(), sizeof(key));
    KeyDerivation::secureZero(decrypted.data(), decrypted.size());
    KeyDerivation::secureZero(&header, sizeof(header));

    Logger::info("Successfully decrypted vault record into: " + destFile.string() +
                 " (" + std::to_string(recoveredSize) + " bytes recovered)");
    return true;
}

VaultStatus VaultManager::inspectStatus() {
    VaultStatus status;
    status.vault_path = m_vaultPath;
    status.is_initialized = std::filesystem::exists(m_metaPath);

    if (status.is_initialized && std::filesystem::exists(m_recordsPath)) {
        for (const auto& entry : std::filesystem::directory_iterator(m_recordsPath)) {
            if (entry.is_regular_file() && entry.path().extension() == ".enc") {
                status.stored_files.push_back(entry.path().stem().string());
                status.total_vault_bytes += entry.file_size();
            }
        }
        status.file_count = status.stored_files.size();
    }

    // Inspect kernel driver status
    UniqueFd devFd = openKernelDevice();
    if (devFd.valid()) {
        status.kernel_driver_available = true;
        struct kvault_status_param kstatus{};
        if (::ioctl(devFd.get(), KVAULT_IOCTL_GET_STATUS, &kstatus) == 0) {
            status.kernel_driver_version = kstatus.driver_version;
            status.kernel_bytes_transformed = kstatus.bytes_transformed;
        }
    } else {
        status.kernel_driver_available = false;
    }

    return status;
}

bool VaultManager::isKernelDriverLoaded() const {
    return std::filesystem::exists("/dev/kvault");
}

} // namespace kvault
