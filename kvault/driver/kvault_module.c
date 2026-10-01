/**
 * @file kvault_module.c
 * @brief Character device driver & Linux Kernel Crypto API hardware accelerator for KernelVault.
 *
 * Implements the in-kernel cryptographic transformation boundary for kvault.
 * Encapsulates AES-256-CBC transformations, single-process atomic concurrency,
 * mutex-guarded cipher state, and explicit zeroization of key material.
 *
 * Dual licensed under MIT and GPL v2.
 */

#include "kvault_module.h"

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Principal Linux Kernel Engineer <kernel-engineer@kvault.internal>");
MODULE_DESCRIPTION("Cryptographic Hardware Accelerator & Key Isolation Driver for KernelVault");
MODULE_VERSION("1.0.0");

static struct kvault_dev *g_kvault_dev = NULL;

/**
 * kvault_flush_key_material() - Explicitly wipe sensitive key buffers in kernel RAM.
 * @kdev: Pointer to the driver's device structure.
 *
 * Employs memzero_explicit() to prevent the compiler from optimizing out
 * memory wipe operations as dead stores.
 */
void kvault_flush_key_material(struct kvault_dev *kdev)
{
    if (!kdev)
        return;

    memzero_explicit(kdev->session_key, sizeof(kdev->session_key));
    memzero_explicit(kdev->session_iv, sizeof(kdev->session_iv));
    kdev->is_key_set = false;
    pr_info("kvault: Key material securely zeroed in kernel memory.\n");
}

/**
 * kvault_do_cipher_transform() - Perform synchronous skcipher cryptographic transform.
 * @kdev: Pointer to device state.
 * @src: Pointer to source buffer in kernel memory.
 * @dst: Pointer to destination buffer in kernel memory.
 * @length: Length of data to transform in bytes (must be multiple of AES block size).
 * @encrypt: 1 for encryption, 0 for decryption.
 *
 * Return: 0 on success, negative error code on failure.
 */
int kvault_do_cipher_transform(struct kvault_dev *kdev, const u8 *src, u8 *dst,
                              size_t length, int encrypt)
{
    struct skcipher_request *req = NULL;
    DECLARE_CRYPTO_WAIT(wait);
    struct scatterlist sg_src, sg_dst;
    u8 iv[KVAULT_IV_SIZE];
    int err = 0;

    if (!kdev || !kdev->tfm)
        return -EINVAL;

    if (!kdev->is_key_set) {
        pr_err("kvault: Cannot transform without active key.\n");
        return -EACCES;
    }

    if (length % KVAULT_IV_SIZE != 0 || length == 0) {
        pr_err("kvault: Buffer length %zu is not block aligned.\n", length);
        return -EINVAL;
    }

    req = skcipher_request_alloc(kdev->tfm, GFP_KERNEL);
    if (!req) {
        pr_err("kvault: Failed to allocate skcipher request.\n");
        return -ENOMEM;
    }

    /* Make local working copy of IV as skcipher updates IV in-place */
    memcpy(iv, kdev->session_iv, sizeof(iv));

    sg_init_one(&sg_src, src, length);
    sg_init_one(&sg_dst, dst, length);

    skcipher_request_set_callback(req,
                                  CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
                                  crypto_req_done, &wait);

    skcipher_request_set_crypt(req, &sg_src, &sg_dst, length, iv);

    if (encrypt) {
        err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    } else {
        err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
    }

    if (err) {
        pr_err("kvault: Cipher operation failed with code %d\n", err);
    } else {
        kdev->bytes_transformed += length;
        /* Update session IV with latest state for streaming continuity */
        memcpy(kdev->session_iv, iv, sizeof(kdev->session_iv));
    }

    skcipher_request_free(req);
    memzero_explicit(iv, sizeof(iv));
    return err;
}

/**
 * kvault_open() - Open handler with atomic single-process concurrency control.
 * @inode: Inode pointer.
 * @filp: File pointer.
 *
 * Return: 0 on success, -EBUSY if another process already owns the device.
 */
int kvault_open(struct inode *inode, struct file *filp)
{
    struct kvault_dev *kdev = container_of(inode->i_cdev, struct kvault_dev, cdev);

    /* Enforce strict single-process exclusive device ownership */
    if (atomic_cmpxchg(&kdev->device_busy, 0, 1) != 0) {
        pr_warn("kvault: Dual open contention detected! Denying access.\n");
        return -EBUSY;
    }

    filp->private_data = kdev;
    pr_info("kvault: Device opened exclusively by PID %d\n", current->pid);
    return 0;
}

/**
 * kvault_release() - Release handler executed when process closes /dev/kvault.
 * @inode: Inode pointer.
 * @filp: File pointer.
 *
 * Return: 0 on success.
 */
int kvault_release(struct inode *inode, struct file *filp)
{
    struct kvault_dev *kdev = filp->private_data;

    if (kdev) {
        mutex_lock(&kdev->cipher_mutex);
        /* Security Hygiene: Erase key material upon session close */
        kvault_flush_key_material(kdev);
        kdev->io_buf_len = 0;
        mutex_unlock(&kdev->cipher_mutex);

        /* Release atomic lock so subsequent processes may open device */
        atomic_set(&kdev->device_busy, 0);
        pr_info("kvault: Device released by PID %d. Lock freed.\n", current->pid);
    }

    return 0;
}

/**
 * kvault_read() - Read transformed data from kernel buffer.
 * @filp: File pointer.
 * @buf: User-space destination buffer.
 * @count: Number of bytes requested.
 * @f_pos: File position offset.
 *
 * Return: Number of bytes read or error code.
 */
ssize_t kvault_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    struct kvault_dev *kdev = filp->private_data;
    size_t to_copy = 0;
    ssize_t ret = 0;

    if (!kdev)
        return -EINVAL;

    mutex_lock(&kdev->cipher_mutex);

    if (kdev->io_buf_len == 0) {
        mutex_unlock(&kdev->cipher_mutex);
        return 0; /* EOF / No pending data */
    }

    to_copy = min(count, kdev->io_buf_len);
    if (copy_to_user(buf, kdev->io_buffer, to_copy)) {
        pr_err("kvault: Failed copy_to_user in kvault_read.\n");
        ret = -EFAULT;
        goto out_unlock;
    }

    /* Shift remaining data if partial read */
    if (to_copy < kdev->io_buf_len) {
        memmove(kdev->io_buffer, kdev->io_buffer + to_copy, kdev->io_buf_len - to_copy);
        kdev->io_buf_len -= to_copy;
    } else {
        kdev->io_buf_len = 0;
    }

    ret = to_copy;

out_unlock:
    mutex_unlock(&kdev->cipher_mutex);
    return ret;
}

/**
 * kvault_write() - Write plaintext or ciphertext to kernel buffer and transform.
 * @filp: File pointer.
 * @buf: User-space source buffer.
 * @count: Number of bytes to write.
 * @f_pos: File position offset.
 *
 * Return: Number of bytes written or error code.
 */
ssize_t kvault_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    struct kvault_dev *kdev = filp->private_data;
    size_t chunk = 0;
    ssize_t ret = 0;
    int err = 0;

    if (!kdev)
        return -EINVAL;

    if (count > KVAULT_MAX_CHUNK_SIZE)
        return -EINVAL;

    mutex_lock(&kdev->cipher_mutex);

    if (!kdev->is_key_set) {
        pr_err("kvault: Write attempted without configured key.\n");
        ret = -EACCES;
        goto out_unlock;
    }

    chunk = count;
    if (copy_from_user(kdev->io_buffer, buf, chunk)) {
        pr_err("kvault: Failed copy_from_user in kvault_write.\n");
        ret = -EFAULT;
        goto out_unlock;
    }

    /* Transform buffer in-place within kernel memory */
    err = kvault_do_cipher_transform(kdev, kdev->io_buffer, kdev->io_buffer, chunk,
                                    kdev->cipher_mode == KVAULT_MODE_ENCRYPT);
    if (err) {
        pr_err("kvault: Transform failed in kvault_write: %d\n", err);
        ret = err;
        goto out_unlock;
    }

    kdev->io_buf_len = chunk;
    ret = chunk;

out_unlock:
    mutex_unlock(&kdev->cipher_mutex);
    return ret;
}

/**
 * kvault_ioctl() - Handles user-space control commands.
 * @filp: File pointer.
 * @cmd: IOCTL command identifier.
 * @arg: User-space parameter address.
 *
 * Return: 0 on success, negative error on failure.
 */
long kvault_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct kvault_dev *kdev = filp->private_data;
    long ret = 0;

    if (!kdev)
        return -EINVAL;

    switch (cmd) {
    case KVAULT_IOCTL_SET_KEY: {
        struct kvault_key_param key_param;
        int err;

        if (copy_from_user(&key_param, (void __user *)arg, sizeof(key_param)))
            return -EFAULT;

        if (key_param.key_len != KVAULT_KEY_SIZE) {
            pr_err("kvault: Invalid key length %u (expected %u)\n",
                   key_param.key_len, KVAULT_KEY_SIZE);
            return -EINVAL;
        }

        mutex_lock(&kdev->cipher_mutex);
        memcpy(kdev->session_key, key_param.key, KVAULT_KEY_SIZE);

        /* Configure key in skcipher transformation context */
        err = crypto_skcipher_setkey(kdev->tfm, kdev->session_key, KVAULT_KEY_SIZE);
        if (err) {
            pr_err("kvault: crypto_skcipher_setkey failed: %d\n", err);
            kvault_flush_key_material(kdev);
            mutex_unlock(&kdev->cipher_mutex);
            return err;
        }

        kdev->is_key_set = true;
        mutex_unlock(&kdev->cipher_mutex);

        /* Wipe stack copy of user-supplied key immediately */
        memzero_explicit(&key_param, sizeof(key_param));
        pr_info("kvault: 256-bit AES master key configured successfully.\n");
        break;
    }

    case KVAULT_IOCTL_FLUSH_KEY: {
        mutex_lock(&kdev->cipher_mutex);
        kvault_flush_key_material(kdev);
        mutex_unlock(&kdev->cipher_mutex);
        break;
    }

    case KVAULT_IOCTL_SET_IV: {
        struct kvault_iv_param iv_param;

        if (copy_from_user(&iv_param, (void __user *)arg, sizeof(iv_param)))
            return -EFAULT;

        if (iv_param.iv_len != KVAULT_IV_SIZE) {
            pr_err("kvault: Invalid IV length %u (expected %u)\n",
                   iv_param.iv_len, KVAULT_IV_SIZE);
            return -EINVAL;
        }

        mutex_lock(&kdev->cipher_mutex);
        memcpy(kdev->session_iv, iv_param.iv, KVAULT_IV_SIZE);
        mutex_unlock(&kdev->cipher_mutex);
        break;
    }

    case KVAULT_IOCTL_SET_MODE: {
        int mode = 0;
        if (get_user(mode, (int __user *)arg))
            return -EFAULT;

        if (mode != KVAULT_MODE_ENCRYPT && mode != KVAULT_MODE_DECRYPT)
            return -EINVAL;

        mutex_lock(&kdev->cipher_mutex);
        kdev->cipher_mode = mode;
        mutex_unlock(&kdev->cipher_mutex);
        break;
    }

    case KVAULT_IOCTL_GET_STATUS: {
        struct kvault_status_param status;
        memset(&status, 0, sizeof(status));

        mutex_lock(&kdev->cipher_mutex);
        status.is_key_set = kdev->is_key_set ? 1 : 0;
        status.cipher_mode = kdev->cipher_mode;
        status.bytes_transformed = kdev->bytes_transformed;
        status.driver_version = DRIVER_VERSION;
        mutex_unlock(&kdev->cipher_mutex);

        if (copy_to_user((void __user *)arg, &status, sizeof(status)))
            return -EFAULT;
        break;
    }

    case KVAULT_IOCTL_TRANSFORM: {
        struct kvault_transform_param trans;
        u8 *k_buf = NULL;
        int err = 0;

        if (copy_from_user(&trans, (void __user *)arg, sizeof(trans)))
            return -EFAULT;

        if (trans.length == 0 || trans.length > KVAULT_MAX_CHUNK_SIZE ||
            trans.length % KVAULT_IV_SIZE != 0) {
            pr_err("kvault: Invalid transform length %u\n", trans.length);
            return -EINVAL;
        }

        if (!trans.src || !trans.dst)
            return -EINVAL;

        k_buf = kmalloc(trans.length, GFP_KERNEL);
        if (!k_buf)
            return -ENOMEM;

        if (copy_from_user(k_buf, trans.src, trans.length)) {
            kfree(k_buf);
            return -EFAULT;
        }

        mutex_lock(&kdev->cipher_mutex);
        err = kvault_do_cipher_transform(kdev, k_buf, k_buf, trans.length,
                                        trans.mode == KVAULT_MODE_ENCRYPT);
        mutex_unlock(&kdev->cipher_mutex);

        if (!err) {
            if (copy_to_user(trans.dst, k_buf, trans.length))
                err = -EFAULT;
        }

        memzero_explicit(k_buf, trans.length);
        kfree(k_buf);
        ret = err;
        break;
    }

    default:
        pr_warn("kvault: Unknown IOCTL command 0x%x\n", cmd);
        ret = -ENOTTY;
        break;
    }

    return ret;
}

static const struct file_operations kvault_fops = {
    .owner          = THIS_MODULE,
    .open           = kvault_open,
    .release        = kvault_release,
    .read           = kvault_read,
    .write          = kvault_write,
    .unlocked_ioctl = kvault_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = kvault_ioctl,
#endif
};

/**
 * kvault_init() - Driver entry point invoked during insmod.
 *
 * Return: 0 on success, negative error on failure.
 */
int kvault_init(void)
{
    int ret = 0;
    struct kvault_dev *kdev = NULL;

    pr_info("kvault: Initializing driver v1.0.0...\n");

    kdev = kzalloc(sizeof(*kdev), GFP_KERNEL);
    if (!kdev) {
        pr_err("kvault: Memory allocation failed for device context.\n");
        return -ENOMEM;
    }

    mutex_init(&kdev->cipher_mutex);
    atomic_set(&kdev->device_busy, 0);
    kdev->cipher_mode = KVAULT_MODE_ENCRYPT;

    /* Allocate internal IO chunk buffer */
    kdev->io_buffer = kzalloc(KVAULT_MAX_CHUNK_SIZE, GFP_KERNEL);
    if (!kdev->io_buffer) {
        pr_err("kvault: Failed to allocate io_buffer.\n");
        ret = -ENOMEM;
        goto err_free_kdev;
    }

    /* Allocate Linux Kernel Crypto API skcipher transform */
    kdev->tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
    if (IS_ERR(kdev->tfm)) {
        pr_err("kvault: Failed to allocate skcipher cbc(aes): %ld\n", PTR_ERR(kdev->tfm));
        ret = PTR_ERR(kdev->tfm);
        goto err_free_io_buf;
    }

    /* Dynamically allocate major/minor numbers */
    ret = alloc_chrdev_region(&kdev->dev_num, 0, 1, DRIVER_NAME);
    if (ret < 0) {
        pr_err("kvault: alloc_chrdev_region failed: %d\n", ret);
        goto err_free_tfm;
    }

    /* Initialize and register character device */
    cdev_init(&kdev->cdev, &kvault_fops);
    kdev->cdev.owner = THIS_MODULE;
    ret = cdev_add(&kdev->cdev, kdev->dev_num, 1);
    if (ret < 0) {
        pr_err("kvault: cdev_add failed: %d\n", ret);
        goto err_unreg_chrdev;
    }

    /* Create sysfs class with Linux 6.4+ version-adaptive signature */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    kdev->dev_class = class_create(CLASS_NAME);
#else
    kdev->dev_class = class_create(THIS_MODULE, CLASS_NAME);
#endif

    if (IS_ERR(kdev->dev_class)) {
        ret = PTR_ERR(kdev->dev_class);
        pr_err("kvault: class_create failed: %d\n", ret);
        goto err_del_cdev;
    }

    /* Automatically instantiate /dev/kvault device node */
    kdev->device = device_create(kdev->dev_class, NULL, kdev->dev_num, NULL, DRIVER_NAME);
    if (IS_ERR(kdev->device)) {
        ret = PTR_ERR(kdev->device);
        pr_err("kvault: device_create failed: %d\n", ret);
        goto err_destroy_class;
    }

    g_kvault_dev = kdev;
    pr_info("kvault: Driver loaded successfully. Major: %d, Minor: %d (/dev/%s created)\n",
            MAJOR(kdev->dev_num), MINOR(kdev->dev_num), DRIVER_NAME);
    return 0;

err_destroy_class:
    class_destroy(kdev->dev_class);
err_del_cdev:
    cdev_del(&kdev->cdev);
err_unreg_chrdev:
    unregister_chrdev_region(kdev->dev_num, 1);
err_free_tfm:
    crypto_free_skcipher(kdev->tfm);
err_free_io_buf:
    kfree(kdev->io_buffer);
err_free_kdev:
    kfree(kdev);
    return ret;
}

/**
 * kvault_exit() - Driver cleanup handler invoked during rmmod.
 */
void kvault_exit(void)
{
    if (g_kvault_dev) {
        pr_info("kvault: Unloading driver...\n");

        /* Wipe and destroy cryptographic resources */
        kvault_flush_key_material(g_kvault_dev);

        if (g_kvault_dev->device)
            device_destroy(g_kvault_dev->dev_class, g_kvault_dev->dev_num);

        if (g_kvault_dev->dev_class)
            class_destroy(g_kvault_dev->dev_class);

        cdev_del(&g_kvault_dev->cdev);
        unregister_chrdev_region(g_kvault_dev->dev_num, 1);

        if (g_kvault_dev->tfm)
            crypto_free_skcipher(g_kvault_dev->tfm);

        if (g_kvault_dev->io_buffer) {
            memzero_explicit(g_kvault_dev->io_buffer, KVAULT_MAX_CHUNK_SIZE);
            kfree(g_kvault_dev->io_buffer);
        }

        mutex_destroy(&g_kvault_dev->cipher_mutex);
        kfree(g_kvault_dev);
        g_kvault_dev = NULL;

        pr_info("kvault: Driver unloaded cleanly.\n");
    }
}

module_init(kvault_init);
module_exit(kvault_exit);
