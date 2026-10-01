# KernelVault User Manual

Welcome to KernelVault! This manual is designed for users who need to securely store and retrieve their files using the `kvault` command-line tool. You don't need to know how the underlying Linux kernel works to use KernelVault effectively—this guide will walk you through everything you need to know.

## What is KernelVault?
KernelVault is a highly secure storage system. When you use it to encrypt a file, it places a virtual "padlock" on your data. The unique feature of KernelVault is that the lock is opened and closed deep inside the operating system (the kernel), making it virtually impossible for hackers, malware, or memory scrapers to steal your password.

---

## Getting Started

### 1. Initializing a Vault
Before you can store files, you need a safe place to put them. This is called a "vault".

To create a new vault directory:
```bash
kvault init --vault /path/to/my_vault
```
* **What this does:** It creates a secure folder at the path you specified. Only you (the owner) will have permission to read or write inside this folder.

### 2. Encrypting a File
To securely lock a file and store it in your vault:
```bash
kvault encrypt --in my_secret_document.pdf --vault /path/to/my_vault
```
* **What to expect:** The system will prompt you to enter a Master Password. 
* **Important:** Do not lose this password! KernelVault uses military-grade encryption; without the password, the file cannot be recovered by anyone (not even system administrators).
* **Crash Safety:** If your computer loses power while encrypting a large file, don't worry. KernelVault guarantees that your original `my_secret_document.pdf` will remain perfectly intact.

### 3. Decrypting a File
When you need to read your file again, you must decrypt it out of the vault:
```bash
kvault decrypt --file my_secret_document.pdf.kvlt --vault /path/to/my_vault --out restored_document.pdf
```
* **What to expect:** You will be asked for the Master Password you used during encryption.
* **Tamper Proofing:** If someone has maliciously altered the encrypted file, KernelVault will detect the tampering instantly and refuse to decrypt it, keeping your system safe from corrupted data.

### 4. Checking Vault Status
If you want to see a list of the files currently stored in your vault and verify their integrity, run:
```bash
kvault status --vault /path/to/my_vault
```

---

## Frequently Asked Questions (FAQ)

**Q: Can I open a KernelVault encrypted file on Windows or Mac?**
A: No. KernelVault requires a Linux operating system because it utilizes a custom Linux Kernel module to guarantee extreme security. 

**Q: What happens if two people try to encrypt a file at the exact same time?**
A: KernelVault handles this gracefully. It uses internal "locks" so that if two programs try to write to the vault simultaneously, one will safely wait in line instead of corrupting the data.

**Q: Is there a graphical interface?**
A: Yes! You can open the `web/index.html` file in any web browser to view the interactive Engineering Console. While the console is designed to show the technical architecture of the system, it also includes a built-in terminal sandbox where you can practice these commands.
