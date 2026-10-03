# Recruiter Prototype Demonstration

KernelVault is demonstrated from a Linux terminal. The prototype is the C++ CLI working with a C Linux character-device driver; there is no GUI to launch. This walkthrough is designed for a 5–10 minute technical evaluation.

## Prepare before the meeting

Use a disposable Linux VM with kernel headers matching its running kernel. From the repository root:

```bash
sudo apt update
sudo apt install -y build-essential cmake libgtest-dev linux-headers-$(uname -r) kmod
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
make -C driver
sudo insmod driver/kvault.ko
ls -l /dev/kvault
```

Confirm the device node exists and note its permissions. Do not make it world-writable. For this prototype demo, run the CLI through `sudo` if the current account cannot access the node; production access control is outside this prototype's scope. Keep the VM and repository ready before the recruiter joins so installation does not consume the evaluation time.

## Live walkthrough

### 1. State the scope — about 1 minute

Open `README.md` and `docs/ARCHITECTURE.md`. Explain that the user-space program is C++20, the Linux character driver is C, and the driver uses IOCTLs to submit AES-CBC transformations to the Linux Kernel Crypto API. Key derivation, HMAC record authentication, locks, and atomic persistence are handled in user space.

### 2. Show the Linux CLI — about 1 minute

```bash
uname -sr
./build/kvault --help
```

Point out the four commands: `init`, `encrypt`, `decrypt`, and `status`.

### 3. Prove the driver is available — about 1 minute

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

### 4. Demonstrate the file round trip — about 2 minutes

```bash
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

### 5. Show rejection behavior and implementation — about 2–3 minutes

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

If time allows, show relevant source files: `src/main.cpp`, `src/VaultManager.cpp`, `src/AtomicFileWriter.cpp`, `include/kvault_ioctl.h`, and `driver/kvault_module.c`. Use `docs/TESTING.md` to distinguish the automated user-space tests from manual live-driver evaluation.

## Close the demo

Show the driver messages and unload the module:

```bash
sudo dmesg | grep 'kvault:' | tail -n 20
sudo rmmod kvault
```

Tell the evaluator the main limitations plainly: this is an educational prototype, the passphrase is currently supplied on the command line, live driver tests require a Linux VM and privileges, and no independent security audit has been performed. Do not claim production readiness or hardware acceleration.

## Suggested timing

| Time | Show |
| --- | --- |
| 0:00–1:00 | Requirement mapping and architecture |
| 1:00–2:00 | Linux target and CLI commands |
| 2:00–3:00 | Loaded driver and `/dev/kvault` status |
| 3:00–5:00 | Encrypt, inspect vault status, decrypt, compare |
| 5:00–7:00 | Wrong-passphrase rejection and code paths |
| 7:00–10:00 | Limitations and evaluator questions |
