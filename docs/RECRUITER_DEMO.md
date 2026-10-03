# Recruiter Prototype Demonstration

KernelVault provides a native C++/Qt GUI for guided interaction and a C++ CLI for direct command demonstrations. Both call the same vault engine and can use the C Linux character-device driver. This walkthrough is designed for a 5–10 minute technical evaluation.

## Prepare before the meeting

For a driver-backed demonstration, use a disposable Linux desktop VM with kernel headers matching its running kernel. The CLI and GUI can also be built and demonstrated in Ubuntu on WSL2 with WSLg, but WSL may not support building or loading this out-of-tree driver. Clone under the VM's or WSL's Linux home directory; in WSL do not put the checkout under `/mnt/c` because CMake may fail while generating files. On a headless Linux VM, demonstrate the CLI and skip the GUI walkthrough.

Install the common dependencies and build/test the CLI and GUI from the repository root:

```bash
sudo apt update
sudo apt install -y git build-essential cmake libgtest-dev qt6-base-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DBUILD_GUI=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/kvault --help
```

For the driver-backed VM only, also install matching headers and `kmod`, then build/load the module:

```bash
sudo apt install -y linux-headers-$(uname -r) kmod
make -C driver
sudo insmod driver/kvault.ko
ls -l /dev/kvault
```

Confirm the device node exists and note its permissions. Do not make it world-writable. For this prototype demo, run the CLI through `sudo` if the current account cannot access the node; production access control is outside this prototype's scope. Keep the VM and repository ready before the recruiter joins so installation does not consume the evaluation time.

## Live walkthrough

### 1. State the scope — about 1 minute

Open `README.md` and `docs/ARCHITECTURE.md`. Explain that the user-space program is C++20, the Linux character driver is C, and the driver uses IOCTLs to submit AES-CBC transformations to the Linux Kernel Crypto API. Key derivation, HMAC record authentication, locks, and atomic persistence are handled in user space.

### 2. Show the guided GUI — about 2 minutes

On a Linux desktop or Ubuntu under WSLg, launch the app:

```bash
./build/kvault-gui
```

Choose and initialize a demonstration vault. In **Encrypt a file**, select harmless sample data and enter a demo-only passphrase. Point to the process overview: file selection → encryption and authentication → vault storage. Switch to **Decrypt a record** and show that the flow changes to record selection → HMAC verification → plaintext restoration. The GUI runs operations outside the window's UI thread and reports whether `/dev/kvault` is available; when it is unavailable, the application uses the C++ software fallback.

### 3. Show the Linux CLI — about 1 minute

```bash
uname -sr
./build/kvault --help
```

Point out the four commands: `init`, `encrypt`, `decrypt`, and `status`.

### 4. Prove the driver is available — about 1 minute

```bash
ls -l /dev/kvault
lsmod | grep '^kvault '
```

Create a temporary demonstration directory and use a harmless sample file. The CLI accepts the passphrase as an argument, so use only a demonstration value during the evaluation.

```bash
set -e
DEMO_DIR="$(mktemp -d /tmp/kvault-demo.XXXXXX)"
printf 'KernelVault recruiter demo\n' > "$DEMO_DIR/sample.txt"
sudo ./build/kvault init --vault "$DEMO_DIR/vault"
sudo ./build/kvault status --vault "$DEMO_DIR/vault"
```

In the status output, point out `ACTIVE (/dev/kvault)`. If it says `INACTIVE`, the CLI is using its software fallback; do not describe that run as a driver-backed demonstration.

### 5. Demonstrate the file round trip — about 2 minutes

```bash
set -e
sudo ./build/kvault encrypt \
  --in "$DEMO_DIR/sample.txt" \
  --vault "$DEMO_DIR/vault" \
  --key 'demo-only-passphrase'

sudo ./build/kvault status --vault "$DEMO_DIR/vault"
ls -l "$DEMO_DIR/vault/records"

sudo ./build/kvault decrypt \
  --file sample.txt \
  --vault "$DEMO_DIR/vault" \
  --out "$DEMO_DIR/restored.txt" \
  --key 'demo-only-passphrase'

sudo cmp "$DEMO_DIR/sample.txt" "$DEMO_DIR/restored.txt"
echo 'Round trip verified: the restored file matches the source.'
```

Explain that version 2 records authenticate their header and ciphertext with HMAC-SHA256. The driver performs the cipher transform; it does not perform the record authentication.

### 6. Show rejection behavior and implementation — about 2 minutes

Show that a wrong passphrase is rejected and no output is committed:

```bash
if sudo ./build/kvault decrypt \
  --file sample.txt \
  --vault "$DEMO_DIR/vault" \
  --out "$DEMO_DIR/wrong-passphrase.txt" \
  --key 'incorrect-demo-passphrase'; then
  echo 'Unexpected: decryption succeeded.'
else
  echo 'Expected: authentication rejected the wrong passphrase.'
fi
test ! -e "$DEMO_DIR/wrong-passphrase.txt"
```

If time allows, show relevant source files: `src/gui_main.cpp`, `src/main.cpp`, `src/VaultManager.cpp`, `src/AtomicFileWriter.cpp`, `include/kvault_ioctl.h`, and `driver/kvault_module.c`. Use `docs/TESTING.md` to distinguish the automated user-space tests from manual live-driver evaluation.

## Close the demo

Show the driver messages and unload the module:

```bash
sudo dmesg | grep 'kvault:' | tail -n 20
sudo rmmod kvault
```

Tell the evaluator the main limitations plainly: this is an educational prototype, the CLI passphrase is supplied on the command line, live driver tests require a Linux VM and privileges, and no independent security audit has been performed. The GUI masks the passphrase field but does not make this an audited production security product. Do not claim production readiness or hardware acceleration.

## Suggested timing

| Time | Show |
| --- | --- |
| 0:00–1:00 | Requirement mapping and architecture |
| 1:00–3:00 | Guided GUI flow for encryption and decryption |
| 3:00–4:00 | Linux CLI commands |
| 4:00–5:00 | Loaded driver and `/dev/kvault` status |
| 5:00–7:00 | CLI file round trip and wrong-passphrase rejection |
| 7:00–10:00 | Source walkthrough, limitations, and evaluator questions |
