/**
 * @file kvault_module.h
 * @brief Internal Linux Kernel device driver headers and data structures for kvault.
 *
 * Provides device state definitions, synchronization primitives, crypto
 * transform abstractions, and forward declarations for the kvault kernel module.
 */

#ifndef KVAULT_MODULE_H
#define KVAULT_MODULE_H

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <linux/version.h>

#include "../include/kvault_ioctl.h"

#define DRIVER_NAME "kvault"
#define CLASS_NAME  "kvault_class"
#define DRIVER_VERSION 0x00010000

/**
 * struct kvault_dev - Per-device runtime state for kvault
 * @dev_num: Dynamically allocated major/minor device numbers
 * @cdev: Character device structure
 * @dev_class: Sysfs class pointer
 * @device: Sysfs device pointer
 * @tfm: Linux Kernel Crypto API skcipher transform handle
 * @cipher_mutex: Protects session state and cipher hardware transform pipeline
 * @device_busy: Atomic flag enforcing single-process exclusive device open
 * @session_key: Active AES-256 key stored in pinned kernel RAM
 * @session_iv: Active 128-bit initialization vector
 * @is_key_set: Flag indicating if a valid key has been loaded
 * @cipher_mode: Operational mode (KVAULT_MODE_ENCRYPT or KVAULT_MODE_DECRYPT)
 * @bytes_transformed: Total bytes processed during active session
 * @io_buffer: Temporary kernel buffer for read/write streaming operations
 * @io_buf_len: Amount of valid data currently stored in @io_buffer
 */
struct kvault_dev {
    dev_t dev_num;
    struct cdev cdev;
    struct class *dev_class;
    struct device *device;
    struct crypto_skcipher *tfm;
    struct mutex cipher_mutex;
    atomic_t device_busy;
    u8 session_key[KVAULT_KEY_SIZE];
    u8 session_iv[KVAULT_IV_SIZE];
    bool is_key_set;
    int cipher_mode;
    u64 bytes_transformed;
    u8 *io_buffer;
    size_t io_buf_len;
};

/* Module lifecycle hooks */
int kvault_init(void);
void kvault_exit(void);

/* File operations forward declarations */
int kvault_open(struct inode *inode, struct file *filp);
int kvault_release(struct inode *inode, struct file *filp);
ssize_t kvault_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos);
ssize_t kvault_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);
long kvault_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

/* Cryptographic helper functions */
int kvault_do_cipher_transform(struct kvault_dev *kdev, const u8 *src, u8 *dst,
                              size_t length, int encrypt);
void kvault_flush_key_material(struct kvault_dev *kdev);

#endif /* KVAULT_MODULE_H */
