# Prototype Runbook & End-to-End Trials

This runbook outlines the exact steps required to deploy the KernelVault prototype, compile the system, load the kernel driver, and execute start-to-end tests to verify the proof-of-work.

## Stage 1: Build and Initialization

### 1.1 Compile the Codebase
Ensure you have CMake (3.20+), Make, and a C++20 compatible compiler installed, along with the Linux kernel headers.

```bash
cd kvault
mkdir build
cd build
cmake ..
make
```

### 1.2 Load the Kernel Module
KernelVault relies on a custom kernel character driver to enforce the security boundary. You must load this module as root.

```bash
# Insert the kernel module
sudo insmod driver/sec_crypto.ko

# Verify the device node was created
ls -l /dev/kvault

# Check the kernel ring buffer to ensure successful initialization
dmesg | tail -n 5
```
**Expected Output in dmesg:**
```text
[  123.456789] kvault: character device registered with major 243, minor 0
[  123.456801] kvault: skcipher allocated ("cbc(aes)") - crypto hardware ready
```

---

## Stage 2: End-to-End Functional Trials

### Trial A: Encrypting and Decrypting a File
This trial proves that the system can successfully ingest a plaintext file, apply AES-256-CBC encryption via the kernel, and restore it byte-for-byte.

1. **Create a secure vault directory:**
   ```bash
   ./kvault init --vault /tmp/secure_vault
   ```

2. **Create a test file:**
   ```bash
   echo "This is highly classified prototype data." > secret.txt
   ```

3. **Encrypt the file:**
   ```bash
   ./kvault encrypt --in secret.txt --vault /tmp/secure_vault
   # When prompted, enter a password, e.g., "MasterKey2026"
   ```

4. **Verify the encrypted output:**
   ```bash
   # Check that the file was created in the vault
   ls -la /tmp/secure_vault/secret.txt.kvlt
   
   # Inspect the 96-byte header to see the "KVLT" magic string
   xxd /tmp/secure_vault/secret.txt.kvlt | head -n 6
   ```

5. **Decrypt the file:**
   ```bash
   ./kvault decrypt --file secret.txt.kvlt --vault /tmp/secure_vault --out restored.txt
   # Enter the same password: "MasterKey2026"
   ```

6. **Verify Data Integrity:**
   ```bash
   diff secret.txt restored.txt
   # If the command returns nothing, the file was perfectly restored!
   ```

### Trial B: Anti-Tamper Authentication (HMAC Verification)
This trial proves that KernelVault detects malicious modifications to the encrypted ciphertext.

1. **Tamper with the encrypted file:**
   ```bash
   # Append garbage bytes to the encrypted file
   echo "malicious_data" >> /tmp/secure_vault/secret.txt.kvlt
   ```

2. **Attempt to decrypt the tampered file:**
   ```bash
   ./kvault decrypt --file secret.txt.kvlt --vault /tmp/secure_vault --out failed_restore.txt
   ```

3. **Expected Result:**
   The `kvault` process will instantly reject the file.
   ```text
   [ERROR] Authentication failed: HMAC-SHA256 signature mismatch. File has been tampered with.
   ```

### Trial C: Interactive Web Dashboard
The web dashboard provides an interactive representation of the system architecture without requiring a live Linux kernel.

1. Open `web/index.html` in any modern web browser.
2. Navigate the multi-page interface to view the **Architecture**, **Binary Frame Dissector**, and **CLI Sandbox**.
3. Use the **CLI Sandbox** to run simulated `kvault` commands directly in the browser.

---

## Stage 3: Teardown

When you are finished testing, unload the kernel module to clean up system resources.

```bash
sudo rmmod sec_crypto
dmesg | tail -n 2
# Expected: kvault: driver unloaded successfully
```
