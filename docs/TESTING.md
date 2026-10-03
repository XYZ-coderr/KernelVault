# Build and Test Guide

This document lists the checks available in the repository and their scope. It is a procedure, not a pass report; results should be recorded only after running them on the named environment. Use a Linux filesystem for both the checkout and build directory. In WSL, clone under `$HOME` rather than `/mnt/c` to avoid CMake file-generation permission errors.

## C++ build and unit/integration suite

Install the prerequisites on Debian or Ubuntu, then configure, build, and run CTest from the repository root:

```bash
sudo apt update
sudo apt install -y build-essential cmake libgtest-dev
```

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

GoogleTest is resolved from the system package. CMake falls back to FetchContent when GoogleTest is unavailable, which requires network access.

The current GoogleTest targets cover:

- `UniqueFd`: descriptor ownership, move behavior, close, and release.
- `FileLock`: shared/exclusive POSIX lock lifecycle and move behavior.
- `AtomicFileWriter`: commit, abort, temporary-file cleanup, overwrite, and file permissions.
- `VaultIntegration`: initialization, encryption/decryption round trips, incorrect passphrases, and tampered records.

The record-integrity checks include tampered ciphertext and tampered version 2 header data.

The tests run only on Linux because they exercise POSIX descriptors, locks, and file permissions.

## Sanitizers

Configure an AddressSanitizer/UndefinedBehaviorSanitizer build with:

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON -DENABLE_ASAN=ON
cmake --build build-asan --parallel
ctest --test-dir build-asan --output-on-failure
```

## Kernel module build

Build the out-of-tree module against the running kernel's headers:

```bash
make -C driver
modinfo driver/kvault.ko
```

To target another installed kernel build directory, pass `KDIR=/path/to/kernel/build`.

## Manual driver exercise

Module compilation needs kernel headers for the target kernel. Module loading requires a suitable Linux kernel and root privileges. WSL may not provide the matching headers or permit this module to load; use a disposable Linux VM:

```bash
sudo insmod driver/kvault.ko
ls -l /dev/kvault
./build/kvault status --vault /tmp/kvault-demo
sudo dmesg | tail -n 30
sudo rmmod kvault
```

Exercise encryption and decryption with the driver loaded and compare the restored file to its original. Repeat with the module unloaded to exercise the software fallback. Record the kernel version, compiler, commands, and observed result in the submission report.

## Automated coverage boundary

GitHub Actions builds the user-space application and runs CTest with GCC and Clang. A separate job builds the kernel module against installed Ubuntu headers. CI does not load the module, test live IOCTL behavior, inspect key memory, or establish security against a real attacker. Those claims require separate controlled Linux testing and should not be inferred from a successful build.
