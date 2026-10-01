# System Architecture & Technical Specifications: KernelVault (`kvault`)

**Document Version:** 1.0.0  
**Architect:** Principal Linux Kernel Engineer & C++ Systems Architect  
**Classification:** Core System Architecture  

---

## 1. High-Level Architecture Overview

The **KernelVault (`kvault`)** storage engine is a dual-tier security architecture consisting of:
1. An in-kernel cryptographic acceleration character device driver (`kvault_module`), and
2. A high-assurance POSIX C++20 user-space runtime and command-line engine (`kvault`).

By separating the cryptographic transformation engine into the Linux kernel space and enforcing atomic, transactional persistence in user space, `kvault` guarantees both confidentiality against local user-space attackers and resilience against unexpected system failures or power cuts.

```
+--------------------------------------------------------------------------------+
|                             USER SPACE (C++20 Engine)                          |
|                                                                                |
|  [ CLI Entry Point ] ---> [ VaultManager ] <---> [ KeyDerivation (PBKDF2) ]   |
|          |                        |                                            |
|          v                        +---> [ FileLock (POSIX fcntl RAII) ]        |
|  [ Signal Handler ]               |                                            |
|  (SIGINT/SIGTERM)                 +---> [ AtomicFileWriter (fsync/renameat2) ]|
|          |                        |                                            |
|          v                        v                                            |
|  [ Temporary File Clean ]   [ UniqueFd RAII Handle ]                           |
+-----------------------------------|--------------------------------------------+
                                    | Virtual File System (VFS)
                                    v /dev/kvault
+--------------------------------------------------------------------------------+
|                            LINUX KERNEL SUBSYSTEM                              |
|                                                                                |
|   +------------------------------------------------------------------------+   |
|   | Character Device Driver (kvault_module)                                |   |
|   |                                                                        |   |
|   |   - atomic_cmpxchg() Single-Process Access Arbiter                     |   |
|   |   - Mutex-Guarded Cipher Transformation Context                        |   |
|   |   - IOCTL Handler: KVAULT_IOCTL_SET_KEY / KVAULT_IOCTL_FLUSH_KEY       |   |
|   |   - Zero-Memory Scrubber: memzero_explicit()                           |   |
|   +-----------------------------------|------------------------------------+   |
|                                       v                                        |
|   +------------------------------------------------------------------------+   |
|   | Linux Kernel Crypto API (crypto_alloc_skcipher)                        |   |
|   |   - AES-256-CBC Transform Engine                                       |   |
|   |   - Scatterlist (sg_init_one) & Synchronous crypto_wait_req Completion |   |
|   +------------------------------------------------------------------------+   |
+--------------------------------------------------------------------------------+
                                        | Physical Page Writes
                                        v
+--------------------------------------------------------------------------------+
|                       NVMe / SSD / Ext4 / XFS Storage                          |
+--------------------------------------------------------------------------------+
```

---

## 2. UML Diagrams Reference

The repository includes formal PlantUML diagrams under `docs/architecture/`:
- **Class Diagram:** [`class_diagram.puml`](file:///c:/Users/NUMAN%20RAZA/OneDrive/%E0%B9%80%E0%B8%AD%E0%B8%81%E0%B8%AA%E0%B8%B2%E0%B8%A3/Wipro%20Project/kvault/docs/architecture/class_diagram.puml)
- **Sequence Diagram:** [`sequence_diagram.puml`](file:///c:/Users/NUMAN%20RAZA/OneDrive/%E0%B9%80%E0%B8%AD%E0%B8%81%E0%B8%AA%E0%B8%B2%E0%B8%A3/Wipro%20Project/kvault/docs/architecture/sequence_diagram.puml)
- **State Machine Diagram:** [`state_diagram.puml`](file:///c:/Users/NUMAN%20RAZA/OneDrive/%E0%B9%80%E0%B8%AD%E0%B8%81%E0%B8%AA%E0%B8%B2%E0%B8%A3/Wipro%20Project/kvault/docs/architecture/state_diagram.puml)

---

## 3. Subsystem Breakdown

### 3.1 Kernel Device Driver Subsystem (`driver/`)

The kernel module registers a character device under `/dev/kvault` with dynamic major number assignment:
- **Single-Process Exclusive Concurrency:** Handled in `kvault_open()` via:
  ```c
  if (atomic_cmpxchg(&kdev->device_busy, 0, 1) != 0) {
      pr_warn("kvault: Device busy, access denied.\n");
      return -EBUSY;
  }
  ```
- **Cryptographic Transformation Lifecycle:**
  1. Allocation via `crypto_alloc_skcipher("cbc(aes)", 0, 0)` during module initialization.
  2. Setting 256-bit AES key via `crypto_skcipher_setkey()`.
  3. Chunk processing via `skcipher_request_alloc()`, `sg_init_one()`, and `crypto_skcipher_encrypt()` / `crypto_skcipher_decrypt()`.
  4. Explicit wiping via `memzero_explicit()` on key flush and release.

### 3.2 RAII File Descriptor Wrapper (`UniqueFd`)

Replaces raw integer file descriptors with a zero-overhead, move-only C++20 abstraction:
- Copy operations explicitly deleted (`= delete`).
- Move constructor and move assignment transfer ownership and invalidate source descriptor (`-1`).
- Destructor automatically invokes POSIX `::close()` without leaking descriptors on exceptions or early returns.

### 3.3 POSIX Advisory Locking Engine (`FileLock`)

Wraps POSIX `fcntl()` to guarantee multi-process integrity:
- **Shared Locks (`F_RDLCK`):** Acquired during `decrypt` operations, allowing concurrent non-mutating readers.
- **Exclusive Locks (`F_WRLCK`):** Acquired during `encrypt` operations, preventing simultaneous reads or writes on the same vault artifact.
- **Auto-Release:** Reacquired in RAII scope or automatically released by the Linux kernel when the process terminates.

### 3.4 Atomic Transactional Persistence (`AtomicFileWriter`)

Prevents data corruption or torn writes under sudden power loss or process signals:
1. Opens a temporary file in the same directory: `.tmp.<pid>.<uuid>` with `0600` permissions.
2. Streams encrypted payload chunks.
3. Invokes `fsync(fd)` to guarantee physical disk platter / flash controller flush before metadata changes.
4. Invokes Linux `renameat2(AT_FDCWD, tmp, AT_FDCWD, dest, RENAME_NOREPLACE)` or atomic POSIX `rename()`.
5. Registers with the global signal cleanup table to unlink uncommitted `.tmp` files upon `SIGINT` / `SIGTERM`.

### 3.5 Key Derivation & Memory Hygiene (`KeyDerivation`)

- Uses RFC 2898 PBKDF2-HMAC-SHA256 with 100,000 iterations and a 16-byte cryptographic salt.
- Memory hygiene: User-space buffers holding passwords, salts, and intermediate HMAC keys are explicitly wiped using `explicit_bzero()` / volatile memory fences to prevent compiler dead-store elimination.

---

## 4. Vault Binary Format Specification

Every encrypted record in the vault features a 96-byte authenticated binary header:

| Byte Offset | Field Name | Data Type | Description |
| :--- | :--- | :--- | :--- |
| `0x00 - 0x03` | `magic` | `uint32_t` | Constant magic identifier `0x4B564C54` (`"KVLT"`) |
| `0x04 - 0x07` | `version` | `uint32_t` | Vault header format version (`0x00000001`) |
| `0x08 - 0x17` | `salt` | `uint8_t[16]` | Random 128-bit cryptographic salt |
| `0x18 - 0x27` | `iv` | `uint8_t[16]` | Initialization vector for CBC mode |
| `0x28 - 0x2F` | `original_size` | `uint64_t` | Original unpadded plaintext size (bytes) |
| `0x30 - 0x37` | `payload_size` | `uint64_t` | Total encrypted payload size (bytes) |
| `0x38 - 0x57` | `hmac` | `uint8_t[32]` | SHA-256 HMAC covering payload and header |
| `0x58 - 0x5F` | `reserved` | `uint8_t[8]` | Alignment padding / future extensions |
| `0x60 - EOF` | `payload` | `uint8_t[]` | Streamed AES-256 ciphertext in 64 KiB blocks |
