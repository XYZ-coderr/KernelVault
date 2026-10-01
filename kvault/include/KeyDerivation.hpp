/**
 * @file KeyDerivation.hpp
 * @brief High-assurance Key Derivation and Zero-Trust Memory Hygiene Service for kvault.
 *
 * Implements PBKDF2-HMAC-SHA256 (RFC 2898), cryptographic salt generation,
 * message authentication (HMAC-SHA256), and compiler-barrier memory wiping.
 */

#ifndef KEY_DERIVATION_HPP
#define KEY_DERIVATION_HPP

#include <cstdint>
#include <cstddef>
#include <string_view>
#include <span>
#include <vector>

namespace kvault {

/**
 * @class KeyDerivation
 * @brief Cryptographic key derivation and memory scrub utility.
 */
class KeyDerivation {
public:
    static constexpr size_t KEY_SIZE = 32;       /**< 256-bit AES key size */
    static constexpr size_t SALT_SIZE = 16;      /**< 128-bit salt size */
    static constexpr size_t HMAC_SIZE = 32;      /**< 256-bit HMAC size */
    static constexpr uint32_t DEFAULT_ITERATIONS = 100000; /**< Standard PBKDF2 iteration count */

    /**
     * @brief Derives a 256-bit key from a passphrase and salt using PBKDF2-HMAC-SHA256.
     * @param passphrase Plaintext user passphrase.
     * @param salt Cryptographic salt (minimum 16 bytes recommended).
     * @param outKey Output span of 32 bytes to store the derived key.
     * @param iterations PBKDF2 iteration rounds (defaults to 100,000).
     * @return True if derivation succeeded, false otherwise.
     */
    static bool deriveKeyPbkdf2(std::string_view passphrase,
                                std::span<const uint8_t> salt,
                                std::span<uint8_t, KEY_SIZE> outKey,
                                uint32_t iterations = DEFAULT_ITERATIONS);

    /**
     * @brief Generates cryptographically secure pseudo-random salt.
     * @param outSalt Output span to receive random bytes.
     * @return True on success, false if OS entropy source failed.
     */
    static bool generateSalt(std::span<uint8_t, SALT_SIZE> outSalt);

    /**
     * @brief Generates cryptographically secure pseudo-random initialization vector (IV).
     * @param outIv Output span of 16 bytes.
     * @return True on success, false otherwise.
     */
    static bool generateIv(std::span<uint8_t, 16> outIv);

    /**
     * @brief Computes HMAC-SHA256 over a binary payload.
     * @param key Authentication key.
     * @param data Payload data.
     * @param outHmac Output buffer of 32 bytes for the HMAC tag.
     * @return True on success, false otherwise.
     */
    static bool computeHmacSha256(std::span<const uint8_t> key,
                                 std::span<const uint8_t> data,
                                 std::span<uint8_t, HMAC_SIZE> outHmac);

    /**
     * @brief Verifies HMAC-SHA256 in constant time to prevent timing side-channel attacks.
     * @param key Authentication key.
     * @param data Payload data.
     * @param expectedHmac Expected 32-byte HMAC tag.
     * @return True if tag matches, false otherwise.
     */
    static bool verifyHmacConstantTime(std::span<const uint8_t> key,
                                       std::span<const uint8_t> data,
                                       std::span<const uint8_t, HMAC_SIZE> expectedHmac);

    /**
     * @brief Securely scrubs memory buffer, preventing dead-store elimination by the compiler.
     * @param ptr Pointer to memory buffer.
     * @param length Number of bytes to scrub.
     */
    static void secureZero(void* ptr, size_t length) noexcept;

    /**
     * @brief RAII wrapper for auto-zeroing memory buffer upon destruction.
     */
    template <typename T>
    struct SecureBuffer {
        std::vector<T> data;

        explicit SecureBuffer(size_t size = 0, T val = T{}) : data(size, val) {}
        ~SecureBuffer() {
            if (!data.empty()) {
                secureZero(data.data(), data.size() * sizeof(T));
            }
        }

        SecureBuffer(const SecureBuffer&) = delete;
        SecureBuffer& operator=(const SecureBuffer&) = delete;
        SecureBuffer(SecureBuffer&&) noexcept = default;
        SecureBuffer& operator=(SecureBuffer&&) noexcept = default;

        T* data_ptr() noexcept { return data.data(); }
        const T* data_ptr() const noexcept { return data.data(); }
        size_t size() const noexcept { return data.size(); }
        T& operator[](size_t idx) { return data[idx]; }
        const T& operator[](size_t idx) const { return data[idx]; }
    };
};

} // namespace kvault

namespace secstore = kvault;

#endif // KEY_DERIVATION_HPP
