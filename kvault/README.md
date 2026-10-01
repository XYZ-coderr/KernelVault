# KernelVault (sec-store)

**KernelVault** is a production-grade, highly secure file storage system that bridges a low-level Linux Device Driver (GPL v2) with a modern C++20 user-space storage engine. 

By pushing all cryptographic transformations (AES-256-CBC) into a secure, non-swappable kernel enclave (Ring 0), KernelVault fundamentally eliminates the risk of master keys or plaintext buffers leaking into user-space memory dumps, swap partitions, or `ptrace` debuggers.

---

## 🚀 Key Features

* **Zero-Trust Memory Hygiene:** The master cryptographic key is injected into the kernel via an authenticated IOCTL system call and is immediately zeroed in user-space using `explicit_bzero()`.
* **Three-Phase Atomic Commit:** Crash safety is guaranteed. Even if the system loses power during encryption, the original file is preserved perfectly without "torn writes."
* **Advisory Concurrency Locks:** Safely access files from multiple processes simultaneously, regulated by POSIX `fcntl(2)` locks.
* **Constant-Time Verification:** Every encrypted file begins with a strict 96-byte binary header containing a SHA-256 HMAC tag, verified in constant time to prevent tampering or spoofing.

## 📁 System Requirements
* Operating System: Linux (Kernel 5.4 to 6.x)
* Compiler: GCC 11+ or Clang 14+ (C++20 support required)
* Build System: CMake 3.20+, Make, and Kbuild

## 📖 Documentation
KernelVault is extensively documented for both system operators and low-level kernel engineers:

1. **[User Manual](docs/USER_MANUAL.md)** - A non-technical guide to operating the `kvault` CLI utility.
2. **[Prototype Runbook](docs/PROTOTYPE_RUNBOOK.md)** - A start-to-end trial guide for building, loading the kernel module, and testing the system.
3. **[System Manual](docs/SYSTEM_MANUAL.md)** - The definitive architectural specification for systems engineers.
4. **Engineering Console:** Open `web/index.html` in your browser for an interactive architecture dissector, IOCTL testbed, and threat model analysis.

## 🛠️ Quick Start

To compile the user-space engine and kernel module, run the following:

```bash
mkdir build && cd build
cmake ..
make
```

Once compiled, load the kernel driver (requires root):
```bash
sudo insmod driver/sec_crypto.ko
```

See the [Prototype Runbook](docs/PROTOTYPE_RUNBOOK.md) for full execution traces and testing scenarios.

---
*KernelVault — Strictly Engineered for Production Systems.*
