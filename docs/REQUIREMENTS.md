# Capstone Requirement Traceability

This document maps the capstone rubric to files in the repository. It describes what is present, not unverified claims about external evaluation.

| Rubric item | Repository evidence | Status / boundary |
| --- | --- | --- |
| C/C++ only | `src/`, `include/`, `driver/`, and `tests/` | The implementation is C++20 and C; the optional desktop GUI is a native Qt Widgets C++ target. CMake, Make/Kbuild, GitHub Actions, and Markdown are project tooling and documentation. No browser application or Python utilities are included. |
| Linux only | `CMakeLists.txt`, POSIX source, and Linux driver interfaces | CMake rejects non-Linux targets. The driver must be built against Linux kernel headers and loaded on Linux. |
| Linux device-driver concepts | `driver/kvault_module.c`, `driver/kvault_module.h`, `include/kvault_ioctl.h` | Includes character-device registration, file operations, IOCTL handling, user/kernel copies, mutex/atomic synchronization, and Linux Crypto API requests. Runtime validation requires a Linux host/VM and privileges. |
| Software or hardware architecture | `docs/ARCHITECTURE.md` | Shows the CLI and optional GUI sharing the vault engine, persistence components, software fallback, and kernel boundary. The driver uses the Linux Crypto API; it does not claim dedicated hardware acceleration. |
| GitHub source, README, and run instructions | Repository root, `README.md`, `docs/` | Source and documentation are organized in one directly buildable repository. |
| Completion by 5 October 2026 | GitHub repository and evaluation-ready runbook | Build and driver validation should be completed before submission. |
| 5–10 minute trainer evaluation | `docs/PROTOTYPE_RUNBOOK.md` | Schedule the evaluation directly with the trainer; no external contact is made by this repository. |

## Scope limits to disclose

- This is an educational prototype, not production-reviewed cryptographic software.
- The CLI accepts passphrases on the command line; this can expose them to shell history and process inspection.
- The native GUI is a usability layer over the same vault engine; it does not change the record format or expand the security claims.
- Driver integration is optional at runtime and must be validated on a suitable Linux machine.
- The checked-in GoogleTest suite covers user-space components. It does not load the kernel module or verify kernel memory directly.
- AES-CBC is paired with HMAC-SHA256 for record authentication. The driver itself performs cipher transforms; it does not authenticate vault records.
