# Functional & Non-Functional Specifications: KernelVault (`kvault`)

**Author:** Principal Linux Kernel Engineer & C++ Systems Architect  
**Document Version:** 1.0.0  
**Classification:** Confidential / Production Specification  
**Status:** Approved for Implementation  

---

## 1. Problem Statement & Motivation

Traditional file-encryption solutions (e.g., standard user-space encryption utilities) suffer from several architectural vulnerabilities in modern high-assurance operating environments:

1. **User-Space Key Exposure:** Plaintext cryptographic keys, sensitive transformation buffers, and expansion schedules reside in user-space virtual memory for extended durations. This exposes keys to memory scraping attacks (`/proc/<pid>/mem`, `ptrace` injection, process core dumps, and swap file leakage).
2. **Cold-Boot & Swap Bleed:** Plaintext keys in unpinned user memory can be swapped out to persistent swap partitions or left unscrubbed in dirty cache lines when applications crash unexpectedly.
3. **Tear & Partial Writes:** Standard file manipulation using naive POSIX `open()`, `write()`, and `close()` loops without atomic rename semantics and synchronous cache flushing (`fsync`) leaves files in corrupt, truncated states when processes receive fatal signals (`SIGINT`, `SIGTERM`, `SIGKILL`) or during sudden hardware power loss.
4. **Concurrent Contention:** Multiple CLI processes or service workers accessing the same storage vault simultaneously cause data races, file corruption, or silent data overwrites in the absence of kernel-enforced mandatory or cooperative advisory locking (`fcntl`).

The **KernelVault (`kvault`)** storage engine addresses these vulnerabilities by establishing a hardware-aware, kernel-assisted cryptographic barrier coupled with transactional, atomic POSIX storage primitives.

---

## 2. Threat Model & Security Architecture

### 2.1 Threat Vectors

| Threat ID | Threat Description | Attack Vector | Mitigation Strategy in `kvault` |
| :--- | :--- | :--- | :--- |
| **TH-01** | User-Space Memory Inspection | Non-privileged attacker reads `/proc/$PID/mem` or attaches via `ptrace`. | Ephemeral user-space key lifetime; master key is derived, dispatched to kernel via `ioctl(KVAULT_IOCTL_SET_KEY)`, and immediately purged via `explicit_bzero()`. Transformation is executed inside kernel space. |
| **TH-02** | Core Dump / Swap Exfiltration | Process crashes; core dump written to disk contains cryptographic keys. | `mlock()` applied to key buffers in user space; memory explicitly zeroed in destructors; kernel memory allocated with `kzalloc(GFP_KERNEL)` and scrubbed with `memzero_explicit()`. |
| **TH-03** | Partial Write / Crash Corruption | Power interruption or `kill -9` during vault encryption corrupts destination file. | `AtomicFileWriter` executes transactions: writes to unique `.tmp.<pid>.<uuid>` file, executes `fsync()`, and invokes `renameat2(..., RENAME_NOREPLACE)`. |
| **TH-04** | Concurrent Race Conditions | Simultaneous processes attempt to modify or read the same vault entry. | `FileLock` utilizing POSIX `fcntl()` advisory locks (`F_WRLCK` for writes, `F_RDLCK` for reads) with RAII acquisition and release. |
| **TH-05** | Unauthorized Node Access | Malicious local user interacts with cryptographic device node. | Device node `/dev/kvault` initialized with permissions `0600` (root/owner only) and single-process exclusive access enforced via `atomic_cmpxchg()`. |
| **TH-06** | Ciphertext Tampering | Adversary alters bytes inside stored encrypted files. | Cryptographic chunk framing with SHA-256 HMAC authentication headers verification prior to payload emission. |

### 2.2 Security Boundary: Kernel-Assisted Encryption vs. Pure User-Space

```
+-------------------------------------------------------------------------+
|                              USER SPACE                                 |
|                                                                         |
|  +--------------------+    Password Prompt    +-----------------------+ |
|  | CLI (kvault)       | <==================== | Operator Terminal     | |
|  +--------------------+                       +-----------------------+ |
|            |                                                            |
|            | 1. Derive 256-bit Key (Argon2 / PBKDF2-HMAC-SHA256)        |
|            | 2. explicit_bzero() password                               |
|            v                                                            |
|  +--------------------+                                                 |
|  | VaultManager       |                                                 |
|  |  - AtomicFileWriter|                                                 |
|  |  - FileLock (fcntl)|                                                 |
|  |  - UniqueFd (RAII) |                                                 |
|  +--------------------+                                                 |
|       |          |                                                      |
|       | 3. open()| 4. ioctl(SET_KEY)                                    |
|       |          | 5. write(Plaintext) / read(Ciphertext)               |
+-------|----------|------------------------------------------------------+
        |          |  [SYSTEM CALL BOUNDARY: copy_from_user / copy_to_user]
+-------|----------|------------------------------------------------------+
|       v          v                                                      |
|  +-------------------------------------------------------------------+  |
|  | Character Device Driver: /dev/kvault                              |  |
|  |                                                                   |  |
|  |  - atomic_cmpxchg() Single-Process Gate                           |  |
|  |  - Mutex-Guarded Session Context                                  |  |
|  |  - Kernel Key Memory: kzalloc(..., GFP_KERNEL)                    |  |
|  |  - memzero_explicit() cleanup in release / flush                  |  |
|  |  - Linux Kernel Crypto API: crypto_alloc_skcipher("cbc(aes)")     |  |
|  |  - Scatterlist Engine: sg_init_one & crypto_wait_req              |  |
|  +-------------------------------------------------------------------+  |
|                              KERNEL SPACE                               |
+-------------------------------------------------------------------------+
```

---

## 3. System Deliverables & Boundaries

### 3.1 Device Node Specifications

- **Device Path:** `/dev/kvault`
- **Class Name:** `kvault_class`
- **Device Name:** `kvault`
- **Major Number:** Dynamically allocated via `alloc_chrdev_region()`
- **Minor Number:** `0` (base minor, 1 count)
- **Default Permissions:** `0600` (`S_IRUSR | S_IWUSR`), configurable to `0660` for dedicated `kvault` group via udev / systemd scripts.
- **Concurrency Policy:** Single concurrent open across the entire operating system, enforced using `atomic_cmpxchg(&dev_busy, 0, 1)`. Concurrent `open()` attempts immediately receive `-EBUSY`.

### 3.2 CLI Binary Deliverable

- **Binary Name:** `kvault`
- **Installation Path:** `/usr/local/bin/kvault`
- **Toolchain Standard:** C++20 (`-std=c++20`), compiled with GCC 11+ or Clang 13+.
- **Zero-Dependency Core:** Implements standalone RFC 2898 PBKDF2-HMAC-SHA256 and pure AES-256 fallback engine to guarantee 100% operation in both kernel-driven and mock environments.

---

## 4. Functional Requirements

### 4.1 Vault Management Operations

1. **FR-01: Vault Initialization (`init`)**
   - Command: `kvault init --vault <directory>`
   - Behavior: Creates target directory if non-existent, applies `0700` (`S_IRWXU`) directory permissions, generates `vault.meta` manifest containing vault UUID, salt for master key derivation, and format version identifier.
   - Idempotency: Returns error if vault is already initialized, unless explicitly forced.

2. **FR-02: Secure File Ingestion / Encryption (`encrypt`)**
   - Command: `kvault encrypt --in <source_file> --vault <directory> --key <passphrase>`
   - Behavior:
     - Acquires exclusive write lock (`F_WRLCK`) on `<vault>/<basename>.lock`.
     - Derives 256-bit AES master key using Argon2/PBKDF2 with vault salt and 100,000 rounds.
     - Opens `/dev/kvault`, dispatches key via `KVAULT_IOCTL_SET_KEY`.
     - Reads input file in 64 KiB chunks, pipes through encryption engine.
     - Writes to `.tmp.<pid>.<uuid>` in vault directory with `0600` permissions.
     - Commits pending dirty buffers to NVMe/SATA controller via `fsync()`.
     - Atomically installs final file via `renameat2(..., RENAME_NOREPLACE)`.
     - Flushes kernel driver key via `KVAULT_IOCTL_FLUSH_KEY`.
     - Zeroes user-space key and passphrase buffers with `explicit_bzero()`.

3. **FR-03: Secure File Retrieval / Decryption (`decrypt`)**
   - Command: `kvault decrypt --file <filename> --vault <directory> --out <dest_file> --key <passphrase>`
   - Behavior:
     - Acquires shared read lock (`F_RDLCK`) on `<vault>/<basename>.lock`.
     - Validates cryptographic header and HMAC signature.
     - Configures decryption session in `/dev/kvault`.
     - Streams decrypted plaintext through `AtomicFileWriter` to destination path.
     - Purges kernel key and user buffers upon completion.

4. **FR-04: Vault Status Inspection (`status`)**
   - Command: `kvault status --vault <directory>`
   - Behavior: Scans vault manifest, counts stored files, checks active lockfiles, and verifies whether the `/dev/kvault` kernel acceleration module is loaded and operational.

---

## 5. Non-Functional Requirements & Performance Targets

| Requirement Category | Metric / Constraint | Verification Standard |
| :--- | :--- | :--- |
| **Security Hygiene** | Zero Residual Key Traces | Kernel memory inspected via `/proc/kallsyms` / KASAN; user memory validated via core dump inspection. `memzero_explicit` and `explicit_bzero` mandated. |
| **Crash Resilience** | Zero Torn / Corrupt Files | Process subjected to `kill -9` at random intervals during 1 GiB file encryption. Destination file is either 100% complete or non-existent; temporary `.tmp` files cleanly collected. |
| **Concurrency Isolation** | Single-Process Mutex | Attempting dual `open("/dev/kvault")` returns `-EBUSY`. Attempting dual write on same vault file blocks or fails safely with lock timeout. |
| **Performance Overhead**| Streaming Chunking | Memory footprint capped at $\le 16\text{ MiB}$ regardless of file size ($100\text{ MiB} - 100\text{ GiB}$) using chunked 64 KiB streaming buffers. |
| **Portability & Quality**| Zero Compiler Warnings | Built with `-Wall -Wextra -Werror -Wpedantic`. Passes `cppcheck` and `clang-tidy`. |

---

## 6. IOCTL Interface Specification

Defined in `include/kvault_ioctl.h`:

```c
#define KVAULT_IOC_MAGIC 'k'

#define KVAULT_IOCTL_SET_KEY    _IOW(KVAULT_IOC_MAGIC, 1, struct kvault_key_param)
#define KVAULT_IOCTL_FLUSH_KEY  _IO(KVAULT_IOC_MAGIC,  2)
#define KVAULT_IOCTL_SET_IV     _IOW(KVAULT_IOC_MAGIC, 3, struct kvault_iv_param)
#define KVAULT_IOCTL_SET_MODE   _IOW(KVAULT_IOC_MAGIC, 4, int)
#define KVAULT_IOCTL_GET_STATUS _IOR(KVAULT_IOC_MAGIC, 5, struct kvault_status_param)
#define KVAULT_IOCTL_TRANSFORM  _IOWR(KVAULT_IOC_MAGIC, 6, struct kvault_transform_param)
```

### Return Code Mapping

- `0`: Success.
- `-EBUSY`: Device already opened by another process or cipher engine busy.
- `-EINVAL`: Invalid key length, invalid cipher mode, or null parameters.
- `-ENOMEM`: Kernel page allocation failure in `kzalloc()`.
- `-EFAULT`: Bad user address during `copy_from_user()` or `copy_to_user()`.
- `-EACCES`: Insufficient permissions to access `/dev/kvault`.
