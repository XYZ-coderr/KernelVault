# Linux Prototype Runbook

This guide builds and exercises the KernelVault C++ CLI and Linux character driver on a disposable Linux machine or virtual machine.

For a timed presentation to a recruiter or trainer, follow [`RECRUITER_DEMO.md`](RECRUITER_DEMO.md). The prototype is terminal-operated; no GUI is required.

## 1. Install build dependencies

On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install build-essential cmake libgtest-dev linux-headers-$(uname -r) kmod
```

The CMake test configuration can fetch GoogleTest if it is not installed and network access is available.

## 2. Build the CLI and tests

Run commands from the repository root:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The executable is `build/kvault`.

## 3. Create test input and vault

```bash
printf 'KernelVault evaluation sample\n' > sample.txt
./build/kvault init --vault /tmp/kvault-demo
```

## 4. Encrypt and decrypt

Use a demonstration-only passphrase. The current CLI receives it through `--key`, which can expose it in shell history or process listings.

```bash
./build/kvault encrypt --in sample.txt --vault /tmp/kvault-demo --key 'demo-only-passphrase'
./build/kvault decrypt --file sample.txt --vault /tmp/kvault-demo --out restored.txt --key 'demo-only-passphrase'
cmp sample.txt restored.txt
```

A successful `cmp` exits with status 0 and produces no output. The record is stored at `/tmp/kvault-demo/records/sample.txt.enc`.

## 5. Build and load the Linux driver (optional)

```bash
make -C driver
sudo insmod driver/kvault.ko
ls -l /dev/kvault
sudo dmesg | tail -n 20
```

Run CLI commands as an account allowed to open `/dev/kvault`. The node's permissions depend on the host's device-management policy; do not set world-write permissions. When the device cannot be opened, the CLI uses its software cipher fallback.

Unload the module after evaluation:

```bash
sudo rmmod kvault
```

## 6. Inspect vault status

```bash
./build/kvault status --vault /tmp/kvault-demo
```

## 7. Clean up

```bash
rm -rf /tmp/kvault-demo sample.txt restored.txt build
```

Only run the cleanup command after checking that those paths contain disposable evaluation data.

## Troubleshooting

- **Kernel headers are missing:** install headers matching the target kernel or provide the desired Kbuild directory with `make -C driver KDIR=/path/to/kernel/build`.
- **`insmod` fails:** inspect `sudo dmesg`; check that the module was built against the target kernel and that kernel module loading is permitted.
- **The driver is unavailable to the CLI:** inspect `ls -l /dev/kvault` and use the host's normal group/udev policy to grant access. CLI fallback remains available.
- **Authentication fails:** use the exact passphrase used during encryption and ensure the encrypted record was not modified.
