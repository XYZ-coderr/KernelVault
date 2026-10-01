# KernelVault (`kvault`): Production Systems Architecture & Engineering Reference Manual

**Author:** Principal Linux Kernel Engineer & C++ Systems Architect  
**Classification:** Technical Documentation & Systems Reference  
**Standard:** POSIX.1-2017 / ISO C++20 / Linux Kernel 5.4–6.x Kbuild  
**Status:** Production Standard  

---

## 1. System Overview & Problem Statement

Modern user-space file encryption utilities (e.g., standard GnuPG or command-line wrappers) retain sensitive cryptographic material—including passphrases, PBKDF2 derived keys, AES round keys, and expanded subkeys—directly inside process virtual memory (`Ring 3`). On multi-tenant Linux systems or workstations, this architectural model introduces several severe attack vectors:

1. **User Memory Scraping:** Unprivileged or partially privileged processes can inspect memory via `ptrace(2)` or direct reads to `/proc/$PID/mem`.
2. **Swap Bleed:** During heavy system workloads, unpinned anonymous user-space pages containing plaintext round keys may be paged out to an unencrypted swap partition on disk.
3. **Core Dump Exposure:** An unhandled signal (`SIGSEGV`, `SIGBUS`) triggers core dumps containing sensitive heap and stack key buffers.
4. **Torn Writes & Power Cuts:** Simple `open()` and `write()` operations without atomic metadata swap primitives risk truncating files and causing silent data loss upon system crashes or kernel panics.

### The KernelVault Solution

**KernelVault (`kvault`)** enforces physical memory isolation by dividing the system into two distinct security tiers:
* **The User-Space C++20 Storage Engine:** Manages POSIX filesystem interactions, signal safety, advisory file locks (`fcntl`), chunk streaming (64 KiB), and 3-phase atomic persistence (`renameat2`). Keys are ephemeral in user space (<1 ms lifetime) and immediately scrubbed using `explicit_bzero(3)`.
* **The Linux Kernel Character Driver (`/dev/kvault`):** Operates entirely in `Ring 0`. Master keys and cipher contexts are pinned in non-swappable physical RAM (`kzalloc(GFP_KERNEL)`). Transforms execute via the in-kernel **Linux Crypto API** (`skcipher`), leveraging hardware acceleration (AES-NI / AVX). Device release guarantees memory scrubbing via `memzero_explicit()`.

---

## 2. Directory & Component Layout

```
kvault/
├── CMakeLists.txt                 # Modern C++20 CMake build configuration
├── LICENSE                        # Dual MIT and GPL v2 Licensing
├── README.md                      # Project introduction and quickstart
├── driver/                        # Linux Kernel Out-of-Tree Character Device Driver
│   ├── Kbuild                     # Linux Kbuild module definition
│   ├── Makefile                   # Kernel build invocation wrapper
│   ├── kvault_module.c            # Character device driver implementation (GPL v2)
│   └── kvault_module.h            # Kernel-internal state and synchronization structures
├── include/                       # Public Header Specifications
│   ├── AtomicFileWriter.hpp       # RAII 3-phase atomic swap interface
│   ├── FileLock.hpp               # POSIX advisory lock wrapper (fcntl)
│   ├── KeyDerivation.hpp          # PBKDF2-HMAC-SHA256 & constant-time auth
│   ├── Logger.hpp                 # Thread-safe ANSI systems logging engine
│   ├── UniqueFd.hpp               # Move-only RAII POSIX file descriptor wrapper
│   ├── VaultManager.hpp           # High-level vault framing, chunking & orchestration
│   └── kvault_ioctl.h             # Shared user/kernel binary IOCTL definitions
├── src/                           # User-Space Engine Implementations (C++20)
│   ├── AtomicFileWriter.cpp
│   ├── FileLock.cpp
│   ├── KeyDerivation.cpp
│   ├── UniqueFd.cpp
│   ├── VaultManager.cpp
│   └── main.cpp                   # POSIX CLI entrypoint (subcommands: init, encrypt, decrypt, status, wipe)
├── tests/                         # Automated Verification Suite (GoogleTest)
│   └── test_vault.cpp             # Unit, integration, and stress tests
├── web/                           # Systems Console & Telemetry Dashboard
│   ├── index.html                 # Clean, utilitarian 6-tab enterprise console
│   ├── style.css                  # High-contrast, WCAG AAA compliant design system
│   └── app.js                     # Interactive architecture, IOCTL testbed, dissector & CLI
└── docs/                          # Architecture Specifications & Diagrams
    ├── ARCHITECTURE.md            # Architectural design specifications
    ├── REQUIREMENTS.md            # Functional & non-functional requirements
    ├── TESTING.md                 # Test harness methodology and benchmarks
    └── SYSTEM_MANUAL.md           # This definitive engineering manual
```

---

## 3. Kernel Driver Binary Contract (`kvault_ioctl.h`)

Communication across the user/kernel boundary occurs via standard `ioctl(2)` commands against the `/dev/kvault` device node.

### IOCTL Command Summary

| Command Macro | Direction | Payload Structure | Functional Purpose |
|---|---|---|---|
| `KVAULT_IOCTL_SET_KEY` | `_IOW('k', 1, ...)` | `struct kvault_key_param` | Copies 256-bit AES master key into pinned kernel memory via `copy_from_user()`. |
| `KVAULT_IOCTL_FLUSH_KEY` | `_IO('k', 2)` | None (`void`) | Executes `memzero_explicit()` on active kernel key and resets transform state. |
| `KVAULT_IOCTL_SET_IV` | `_IOW('k', 3, ...)` | `struct kvault_iv_param` | Synchronizes 128-bit Initialization Vector for CBC chaining across 64 KiB chunks. |
| `KVAULT_IOCTL_SET_MODE` | `_IOW('k', 4, int)` | `int` (0=Encrypt, 1=Decrypt) | Toggles active operational transform mode. |
| `KVAULT_IOCTL_GET_STATUS` | `_IOR('k', 5, ...)` | `struct kvault_status_param` | Queries driver health, session throughput, and key status. |
| `KVAULT_IOCTL_TRANSFORM` | `_IOWR('k', 6, ...)` | `struct kvault_transform_param` | Executes synchronous in-kernel AES-256-CBC transformation on user buffer. |

### Binary Structures

```c
struct kvault_key_param {
    uint8_t key[32];   /* 256-bit AES cryptographic key */
    uint32_t key_len;  /* Must equal 32 */
};

struct kvault_iv_param {
    uint8_t iv[16];    /* 128-bit CBC Initialization Vector */
    uint32_t iv_len;   /* Must equal 16 */
};

struct kvault_transform_param {
    const uint8_t *src; /* Pointer to user-space input buffer */
    uint8_t *dst;       /* Pointer to user-space output buffer */
    uint32_t length;    /* Chunk length in bytes (must be multiple of 16) */
    uint32_t mode;      /* 0 = Encrypt, 1 = Decrypt */
};
```

---

## 4. 96-Byte Authenticated Binary Framing Specification

Every encrypted record created by `kvault` is prepended with a rigid 96-byte authenticated binary header. The structure is packed without compiler padding (`#pragma pack(push, 1)`):

```c
#pragma pack(push, 1)
struct VaultHeader {
    uint32_t magic;          /* 0x00: Constant 'KVLT' (0x4B564C54) */
    uint32_t version;        /* 0x04: Binary schema version (0x00000001) */
    uint8_t  salt[16];       /* 0x08: 128-bit PBKDF2 cryptographic salt */
    uint8_t  iv[16];         /* 0x18: 128-bit initial vector for AES-256-CBC */
    uint64_t original_size;  /* 0x28: Plaintext size before PKCS#7 padding */
    uint64_t payload_size;   /* 0x30: Ciphertext length in 64 KiB blocks */
    uint8_t  hmac[32];       /* 0x38: Constant-time SHA-256 HMAC tag */
    uint8_t  reserved[8];    /* 0x58: 64-bit alignment zero-padding */
};
#pragma pack(pop)

static_assert(sizeof(VaultHeader) == 96, "VaultHeader must be exactly 96 bytes");
```

### Authentication Invariant
Decryption **never** initiates without prior constant-time HMAC validation. If the computed SHA-256 HMAC over the header metadata and ciphertext does not match offset `0x38`, execution halts immediately with `-EBADMSG` (Bad Message) before allocating buffers or invoking the cipher.

---

## 5. POSIX Concurrency & Three-Phase Atomic Commit

### Dual-Tier Locking Architecture
1. **Kernel Device Access:** Single-process access to `/dev/kvault` is enforced using an atomic compare-and-swap instruction (`atomic_cmpxchg(&dev->busy, 0, 1)`). Concurrent openers receive `-EBUSY` immediately.
2. **File Record Locking:** The user-space `FileLock` class wraps POSIX `fcntl(2)` using move-only RAII semantics:
   * Write transactions acquire `F_WRLCK` (exclusive).
   * Read transactions acquire `F_RDLCK` (shared).
   * Unlocks occur deterministically upon stack exit or exception dispatch.

### Three-Phase Atomic Persistence (`AtomicFileWriter`)
To prevent corruptions or partial torn writes caused by sudden power cuts, disk unplug events, or `SIGKILL`:
1. **Phase 1 (Staging):** Data is written to a unique temporary file in the vault directory: `.tmp.<filename>.<pid>`.
2. **Phase 2 (Hardware Flush Barrier):** `fsync(tmp_fd)` forces the Linux VFS dirty buffer pages through the storage controller to physical non-volatile silicon (flushing writeback cache).
3. **Phase 3 (Atomic Inode Swap):** `renameat2(dir_fd, tmp, dir_fd, dst, RENAME_NOREPLACE)` executes an atomic directory entry update. If the destination already exists and replacement is disallowed, the operation fails safely without overwriting.

---

## 6. Build, Installation, and Verification

### Prerequisites
* GCC 10+ or Clang 12+ (Full C++20 support)
* CMake 3.20+
* Linux Kernel Headers (`linux-headers-$(uname -r)`)

### 1. Build User-Space Engine & Test Suite
```bash
cd kvault
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j$(nproc)
```

### 2. Build & Install Linux Kernel Driver
```bash
cd ../driver
make
sudo insmod sec_crypto.ko
ls -la /dev/kvault # Verify major 243, permissions 0666
```

### 3. Run Automated GoogleTest Verification Suite
```bash
cd ../build
ctest --output-on-failure
```

### 4. CLI Usage Examples
```bash
# Initialize vault
./kvault init --vault /secure/vault

# Encrypt sensitive document
./kvault encrypt --in secret_spec.pdf --vault /secure/vault --key "StrongPassphrase#2026"

# Audit vault records and HMAC integrity
./kvault status --vault /secure/vault

# Decrypt and restore plaintext
./kvault decrypt --file secret_spec.pdf --vault /secure/vault --out restored.pdf --key "StrongPassphrase#2026"

# Emergency memory scrub
./kvault wipe
```

---

## 7. Web Systems Console

The interactive systems console in [`web/index.html`](file:///c:/Users/NUMAN%20RAZA/OneDrive/เอกสาร/Wipro%20Project/kvault/web/index.html) provides an enterprise engineering workspace designed to strict standards:
* **System Architecture & Data Flow:** Step-by-step pipeline tracer for encrypt, decrypt, and crash simulation.
* **Kernel IOCTL Testbed:** Live dispatcher for all 6 IOCTL commands with real-time `dmesg` ring buffer inspection.
* **96-Byte Binary Frame Dissector:** Interactive byte-level hex dump explorer with struct field highlighting and endianness verification.
* **CLI Sandbox:** VT-style terminal emulator executing authentic `kvault` commands.
* **STRIDE Threat Matrix:** Formal security guarantees covering process isolation, swap bleed prevention, and anti-scraping.
* **Technical Manual:** Built-in searchable systems manual.
