# Linux Prototype Runbook

This guide builds and exercises the KernelVault C++ CLI, optional native Qt desktop interface, and Linux character driver on a Linux machine or virtual machine. The CLI and GUI run on Ubuntu under WSL2 with WSLg; driver loading and testing should use a suitable Linux VM or machine.

For a timed presentation to a recruiter or trainer, follow [`RECRUITER_DEMO.md`](RECRUITER_DEMO.md). The GUI gives reviewers a guided view; the CLI remains available to demonstrate the command interface.

## 1. Install build dependencies

On Debian or Ubuntu, install the CLI, test, and GUI dependencies:

```bash
sudo apt update
sudo apt install -y git build-essential cmake libgtest-dev qt6-base-dev
```

If starting from a fresh clone, clone it into a Linux filesystem directory. In WSL, use `$HOME` (for example, `~/KernelVault`) rather than `/mnt/c`; Windows-mounted paths may prevent CMake from creating generated files. CMake can fetch GoogleTest if the system package cannot be found, which requires network access.

```bash
git clone https://github.com/XYZ-coderr/KernelVault.git "$HOME/KernelVault"
cd "$HOME/KernelVault"
```

## 2. Build the CLI and tests

Run commands from the repository root:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DBUILD_GUI=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The CLI is `build/kvault`; the GUI is `build/kvault-gui`. To build only the CLI, pass `-DBUILD_GUI=OFF` and omit the Qt development package.

## Optional: launch the desktop GUI

On a Linux desktop or Ubuntu under WSLg:

```bash
./build/kvault-gui
```

Choose or initialize a vault, then follow the process overview above the Encrypt and Decrypt tabs. The GUI calls the same C++ vault engine as the CLI.

## 3. Create test input and vault

```bash
set -eu
DEMO_DIR="$(mktemp -d /tmp/kvault-demo.XXXXXX)"
printf 'KernelVault evaluation sample\n' > "$DEMO_DIR/sample.txt"
./build/kvault init --vault "$DEMO_DIR/vault"
```

## 4. Encrypt and decrypt

Use a demonstration-only passphrase. The current CLI receives it through `--key`, which can expose it in shell history or process listings.

```bash
./build/kvault encrypt --in "$DEMO_DIR/sample.txt" --vault "$DEMO_DIR/vault" --key 'demo-only-passphrase'
./build/kvault decrypt --file sample.txt --vault "$DEMO_DIR/vault" --out "$DEMO_DIR/restored.txt" --key 'demo-only-passphrase'
cmp "$DEMO_DIR/sample.txt" "$DEMO_DIR/restored.txt"
echo 'Round trip verified: the restored file matches the source.'
```

A successful `cmp` exits with status 0 and produces no output. With `set -e` enabled above, a mismatch stops the workflow before the success message. Decryption reports the original byte count; confirm the round trip with `cmp` as well. The record is stored at `$DEMO_DIR/vault/records/sample.txt.enc`.

## 5. Build and load the Linux driver (optional)

```bash
sudo apt install -y kmod linux-headers-$(uname -r)
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
./build/kvault status --vault "$DEMO_DIR/vault"
```

## 7. Clean up

```bash
rm -rf -- "$DEMO_DIR"
```

This removes only the temporary demonstration directory created by `mktemp`. Leave the build directory intact if you want to continue using the executable.

## Troubleshooting

- **`cmake` is not recognized in PowerShell:** open the Ubuntu/WSL terminal and run the Linux build commands there.
- **CMake reports `Operation not permitted` under WSL:** clone the repository under `$HOME` and build there. If keeping the checkout under `/mnt/c`, set the build directory to a Linux path such as `$HOME/kvault-build`.
- **GUI does not open in WSL:** confirm WSLg is available; otherwise use a Linux desktop or VM. The CLI continues to work without a graphical display.
- **Driver build or module loading fails in WSL:** use a Linux VM or machine with matching kernel headers and permission to load modules. The CLI and GUI can still run in their user-space fallback mode.
- **`cmp` reports a difference:** confirm decryption used the same passphrase and inspect the command's exit status; `cmp` prints nothing when files match. Check that the reported recovered byte count matches the source file size.
- **Kernel headers are missing:** install headers matching the target kernel or provide the desired Kbuild directory with `make -C driver KDIR=/path/to/kernel/build`.
- **`insmod` fails:** inspect `sudo dmesg`; check that the module was built against the target kernel and that kernel module loading is permitted.
- **The driver is unavailable to the CLI:** inspect `ls -l /dev/kvault` and use the host's normal group/udev policy to grant access. CLI fallback remains available.
- **Authentication fails:** use the exact passphrase used during encryption and ensure the encrypted record was not modified.
