/**
 * @file kvault_ioctl.h
 * @brief Shared User/Kernel IOCTL definitions, command macros, and data structures.
 *
 * This header defines the binary interface contract between the user-space
 * kvault storage engine and the kvault Linux kernel device driver.
 * Compatible with both C (Linux Kernel) and modern C++20 user space.
 */

#ifndef KVAULT_IOCTL_H
#define KVAULT_IOCTL_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Magic character identifier for kvault IOCTL family */
#define KVAULT_IOC_MAGIC 'k'

/** @brief AES-256 key length in bytes */
#define KVAULT_KEY_SIZE 32

/** @brief AES block and IV size in bytes */
#define KVAULT_IV_SIZE 16

/** @brief Maximum single chunk processing size in bytes (64 KiB) */
#define KVAULT_MAX_CHUNK_SIZE (64 * 1024)

/**
 * @enum kvault_cipher_mode
 * @brief Operational mode for the kernel cipher engine
 */
enum kvault_cipher_mode {
    KVAULT_MODE_ENCRYPT = 0,
    KVAULT_MODE_DECRYPT = 1
};

/**
 * @struct kvault_key_param
 * @brief IOCTL payload for passing master key material into kernel space
 */
struct kvault_key_param {
    uint8_t key[KVAULT_KEY_SIZE]; /**< 256-bit AES cryptographic key */
    uint32_t key_len;             /**< Length of key, must equal 32 */
};

/**
 * @struct kvault_iv_param
 * @brief IOCTL payload for configuring cipher initialization vector
 */
struct kvault_iv_param {
    uint8_t iv[KVAULT_IV_SIZE];   /**< 128-bit Initialization Vector */
    uint32_t iv_len;              /**< Length of IV, must equal 16 */
};

/**
 * @struct kvault_transform_param
 * @brief IOCTL payload for in-kernel synchronous buffer transformation
 */
struct kvault_transform_param {
    const uint8_t *src;           /**< Pointer to user-space input buffer */
    uint8_t *dst;                 /**< Pointer to user-space output buffer */
    uint32_t length;              /**< Buffer length (must be multiple of 16) */
    uint32_t mode;                /**< 0 = Encrypt, 1 = Decrypt */
};

/**
 * @struct kvault_status_param
 * @brief IOCTL payload for querying kernel driver health and statistics
 */
struct kvault_status_param {
    uint32_t is_key_set;          /**< 1 if key is loaded, 0 otherwise */
    uint32_t cipher_mode;         /**< Current active cipher mode */
    uint64_t bytes_transformed;   /**< Lifetime bytes processed by session */
    uint32_t driver_version;      /**< Kernel driver protocol version */
};

/* IOCTL Command Definitions */

/**
 * @def KVAULT_IOCTL_SET_KEY
 * @brief Set the 256-bit AES master key in kernel memory.
 */
#define KVAULT_IOCTL_SET_KEY \
    _IOW(KVAULT_IOC_MAGIC, 1, struct kvault_key_param)

/**
 * @def KVAULT_IOCTL_FLUSH_KEY
 * @brief Wipe kernel key memory immediately using memzero_explicit().
 */
#define KVAULT_IOCTL_FLUSH_KEY \
    _IO(KVAULT_IOC_MAGIC, 2)

/**
 * @def KVAULT_IOCTL_SET_IV
 * @brief Configure initialization vector for subsequent streaming transformations.
 */
#define KVAULT_IOCTL_SET_IV \
    _IOW(KVAULT_IOC_MAGIC, 3, struct kvault_iv_param)

/**
 * @def KVAULT_IOCTL_SET_MODE
 * @brief Select encryption or decryption mode.
 */
#define KVAULT_IOCTL_SET_MODE \
    _IOW(KVAULT_IOC_MAGIC, 4, int)

/**
 * @def KVAULT_IOCTL_GET_STATUS
 * @brief Retrieve kernel driver status, session stats, and key status.
 */
#define KVAULT_IOCTL_GET_STATUS \
    _IOR(KVAULT_IOC_MAGIC, 5, struct kvault_status_param)

/**
 * @def KVAULT_IOCTL_TRANSFORM
 * @brief Synchronously transform a chunk of data in kernel memory.
 */
#define KVAULT_IOCTL_TRANSFORM \
    _IOWR(KVAULT_IOC_MAGIC, 6, struct kvault_transform_param)

/* Backwards compatibility aliases */
#define SEC_CRYPTO_IOC_MAGIC      KVAULT_IOC_MAGIC
#define SEC_CRYPTO_KEY_SIZE       KVAULT_KEY_SIZE
#define SEC_CRYPTO_IV_SIZE        KVAULT_IV_SIZE
#define SEC_CRYPTO_MAX_CHUNK_SIZE KVAULT_MAX_CHUNK_SIZE
#define sec_crypto_cipher_mode    kvault_cipher_mode
#define SEC_CRYPTO_MODE_ENCRYPT   KVAULT_MODE_ENCRYPT
#define SEC_CRYPTO_MODE_DECRYPT   KVAULT_MODE_DECRYPT
#define sec_crypto_key_param      kvault_key_param
#define sec_crypto_iv_param       kvault_iv_param
#define sec_crypto_transform_param kvault_transform_param
#define sec_crypto_status_param   kvault_status_param
#define SEC_IOCTL_SET_KEY         KVAULT_IOCTL_SET_KEY
#define SEC_IOCTL_FLUSH_KEY       KVAULT_IOCTL_FLUSH_KEY
#define SEC_IOCTL_SET_IV          KVAULT_IOCTL_SET_IV
#define SEC_IOCTL_SET_MODE        KVAULT_IOCTL_SET_MODE
#define SEC_IOCTL_GET_STATUS      KVAULT_IOCTL_GET_STATUS
#define SEC_IOCTL_TRANSFORM       KVAULT_IOCTL_TRANSFORM

#ifdef __cplusplus
}
#endif

#endif /* KVAULT_IOCTL_H */
