/**
 * @file app.js
 * @brief KernelVault Enterprise Systems Console Logic
 * Strict engineering standard: modular, typed contracts, zero-vibe-coded gimmicks.
 */

'use strict';

/* ==========================================================================
   1. GLOBAL SYSTEM STATE & CONSTANTS
   ========================================================================== */

const KVAULT_CONSTANTS = {
  DEV_NODE: '/dev/kvault',
  MAJOR: 243,
  MINOR: 0,
  MAGIC_STR: 'KVLT',
  MAGIC_HEX: 0x4B564C54,
  VERSION: 1,
  HEADER_SIZE: 96,
  CHUNK_SIZE: 65536, // 64 KiB
  SALT_SIZE: 16,
  IV_SIZE: 16,
  KEY_SIZE: 32,
  HMAC_SIZE: 32,
  ITERATIONS: 100000
};

// Simulated In-Memory Kernel Device Driver State
const KernelDeviceState = {
  loaded: true,
  busy: 0, // atomic_t gate: 0 = unlocked, 1 = locked
  is_key_set: false,
  cipher_mode: 0, // 0 = Encrypt, 1 = Decrypt
  bytes_transformed: 0,
  driver_version: 1,
  active_key_hex: null,
  active_iv_hex: null,
  kmalloc_addr: '0xffff8880042e3000'
};

// Sample Binary Header Frames for the Dissector
const HEADER_SAMPLES = {
  sample1: {
    filename: 'kernel_spec.pdf.kvlt',
    magic: [0x4b, 0x56, 0x4c, 0x54], // "KVLT"
    version: [0x01, 0x00, 0x00, 0x00], // v1 LE
    salt: [0xa3, 0x9f, 0x41, 0x8b, 0x22, 0xd0, 0x5e, 0x11, 0x7b, 0x64, 0x8c, 0xf2, 0x19, 0x03, 0xee, 0x5a],
    iv:   [0x18, 0x4f, 0xd2, 0xb6, 0x73, 0x90, 0x1c, 0x8e, 0x4a, 0x55, 0x3d, 0x21, 0x67, 0xbb, 0x99, 0x04],
    orig_size: [0x50, 0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00], // 139,344 bytes LE
    payload_size: [0x60, 0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00], // 139,360 bytes (aligned to 16B)
    hmac: [
      0x4a, 0x88, 0x21, 0xd9, 0xb3, 0x1e, 0x77, 0x09, 0xc1, 0xf5, 0xe2, 0x3d, 0x90, 0x6a, 0x17, 0x4b,
      0x81, 0x2c, 0x34, 0x7d, 0xe0, 0x55, 0xa9, 0x3f, 0xb2, 0x48, 0x61, 0x9c, 0x08, 0xd3, 0xe1, 0x75
    ],
    reserved: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
  },
  sample2: {
    filename: 'vault_backup.tar.gz.kvlt',
    magic: [0x4b, 0x56, 0x4c, 0x54],
    version: [0x01, 0x00, 0x00, 0x00],
    salt: [0x2f, 0x81, 0x9a, 0x3c, 0x66, 0x44, 0x12, 0xfe, 0xd9, 0x70, 0x2a, 0x5b, 0x88, 0x13, 0xc9, 0x47],
    iv:   [0x91, 0x22, 0x7b, 0xcd, 0x55, 0x0a, 0x8e, 0x14, 0x36, 0x78, 0xf1, 0xe2, 0x49, 0x60, 0xaa, 0x83],
    orig_size: [0xa0, 0x5b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00], // 547,744 bytes LE
    payload_size: [0xb0, 0x5b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00], // 547,760 bytes
    hmac: [
      0x9c, 0x12, 0xfa, 0x48, 0x20, 0x66, 0xbd, 0x31, 0x78, 0xa4, 0x09, 0xee, 0x5c, 0x11, 0xb7, 0x83,
      0x42, 0x70, 0x8d, 0x19, 0xfa, 0x23, 0x90, 0xcc, 0x3e, 0x5b, 0x64, 0x18, 0x71, 0x99, 0x44, 0x02
    ],
    reserved: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
  }
};

/* ==========================================================================
   2. DOM UTILITIES & HELPERS
   ========================================================================== */

const $ = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KiB', 'MiB', 'GiB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function getKernelTimestamp() {
  const t = (performance.now() / 1000).toFixed(6);
  return `[${t.padStart(12, ' ')}]`;
}

function appendKernelLog(msg, type = 'log-kernel') {
  const container = $('ioctl-klog');
  if (!container) return;
  const entry = document.createElement('div');
  entry.className = `log-entry ${type}`;
  entry.textContent = `${getKernelTimestamp()} kvault: ${msg}`;
  container.appendChild(entry);
  container.scrollTop = container.scrollHeight;
}

/* ==========================================================================
   3. TAB NAVIGATION CONTROLLER
   ========================================================================== */

function initNavigation() {
  // Docs internal anchor smooth scrolling
  const docLinks = $$('.docs-nav-link');
  docLinks.forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      docLinks.forEach(l => l.classList.remove('active'));
      link.classList.add('active');
      const targetSec = $(link.getAttribute('href').substring(1));
      if (targetSec) {
        targetSec.scrollIntoView({ behavior: 'smooth' });
      }
    });
  });

  // Theme toggle
  const themeBtn = $('btn-theme-toggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      document.body.classList.toggle('theme-light');
      const isLight = document.body.classList.contains('theme-light');
      localStorage.setItem('kvault-theme', isLight ? 'light' : 'dark');
    });
    if (localStorage.getItem('kvault-theme') === 'light') {
      document.body.classList.add('theme-light');
    }
  }
}

/* ==========================================================================
   4. SYSTEM ARCHITECTURE & DATA FLOW SIMULATOR
   ========================================================================== */

let isPipelineRunning = false;

function setPipelineStatus(badgeText, badgeClass, descText) {
  const badge = $('flow-badge');
  const desc = $('flow-desc');
  if (badge) {
    badge.textContent = badgeText;
    badge.className = `status-indicator-badge ${badgeClass}`;
  }
  if (desc) desc.textContent = descText;
}

function clearAllPipelineHighlights() {
  $$('.arch-node').forEach(n => n.classList.remove('node-highlight', 'node-fault'));
  $$('.syscall-step').forEach(s => s.classList.remove('step-active'));
}

async function runEncryptPipelineTrace() {
  if (isPipelineRunning) return;
  isPipelineRunning = true;
  clearAllPipelineHighlights();

  try {
    // Step 1: Userland Process
    setPipelineStatus('STEP 1/7', 'stat-active', 'CLI Entry: Ingesting passphrase via getpass(), prctl(PR_SET_DUMPABLE, 0) active to prevent core dumps.');
    $('node-cli').classList.add('node-highlight');
    $('stat-pass-mem').textContent = 'Active in stack buffer (masked)';
    await sleep(900);

    // Step 2: PBKDF2 Key Derivation
    setPipelineStatus('STEP 2/7', 'stat-active', 'KeyDerivation: Executing 100,000 rounds of PBKDF2-HMAC-SHA256 with 128-bit hardware entropy salt.');
    $('node-kdf').classList.add('node-highlight');
    $('stat-kdf-state').textContent = '256-bit Key Derived';
    await sleep(1000);

    // Step 3: Open /dev/kvault & Atomic Gate
    setPipelineStatus('STEP 3/7', 'stat-active', 'System Call: open("/dev/kvault") triggers driver kvault_open(), executing atomic_cmpxchg(&dev->busy, 0, 1).');
    $('step-open').classList.add('step-active');
    $('node-kdev').classList.add('node-highlight');
    $('telem-gate-val').textContent = 'LOCKED (1)';
    $('stat-gate-state').textContent = 'Locked to PID 1024';
    await sleep(900);

    // Step 4: IOCTL Key Injection & Userland Memory Wipe
    setPipelineStatus('STEP 4/7', 'stat-active', 'Key Handoff: ioctl(KVAULT_IOCTL_SET_KEY) transfers key to kzalloc(GFP_KERNEL) RAM. explicit_bzero() wipes user RAM.');
    $('step-ioctl-key').classList.add('step-active');
    $('node-kmem').classList.add('node-highlight');
    $('stat-pass-mem').textContent = 'Zeroed via explicit_bzero';
    $('stat-kdf-state').textContent = 'Memory Cleared (<1ms lifetime)';
    appendKernelLog('ioctl SET_KEY: 256-bit key received via copy_from_user(), saved to pinned context');
    await sleep(1000);

    // Step 5: VaultManager Chunker & Advisory Lock
    setPipelineStatus('STEP 5/7', 'stat-active', 'Locking & Chunking: POSIX fcntl(F_SETLK, F_WRLCK) acquired. Source payload segmented into 64 KiB chunks.');
    $('node-lock').classList.add('node-highlight');
    $('node-vaultmgr').classList.add('node-highlight');
    $('stat-lock-state').textContent = 'F_WRLCK held exclusively';
    $('stat-chunk-state').textContent = 'Streaming 64 KiB blocks';
    await sleep(900);

    // Step 6: Kernel Crypto Engine & Scatterlist Transform
    setPipelineStatus('STEP 6/7', 'stat-active', 'Kernel Transformation: AES-256-CBC executed via Linux Crypto API skcipher with zero-copy scatterlists.');
    $('step-io-chunks').classList.add('step-active');
    $('node-cryptoapi').classList.add('node-highlight');
    $('node-scatterlist').classList.add('node-highlight');
    $('stat-crypto-mode').textContent = 'Active: AES-256-CBC Synchronous';
    appendKernelLog('transform: 65536 bytes encrypted via crypto_skcipher_encrypt()');
    await sleep(1100);

    // Step 7: Atomic 3-Phase Persistence
    setPipelineStatus('STEP 7/7', 'stat-active', 'Atomic Commit: fsync() flushes disk writeback cache. renameat2(RENAME_NOREPLACE) atomically commits file record.');
    $('step-fsync').classList.add('step-active');
    $('step-rename').classList.add('step-active');
    $('node-atomic').classList.add('node-highlight');
    $('node-storage').classList.add('node-highlight');
    $('stat-tx-state').textContent = 'Committed: renameat2() successful';
    await sleep(900);

    // Completion & Driver Cleanup
    $('step-close').classList.add('step-active');
    appendKernelLog('close: memzero_explicit() wiped session key; atomic_set(&busy, 0)');
    $('telem-gate-val').textContent = 'UNLOCKED (0)';
    $('stat-gate-state').textContent = 'atomic_cmpxchg(&busy, 0, 1)';
    $('stat-lock-state').textContent = 'No Active Locks (Released via RAII)';
    $('stat-chunk-state').textContent = 'Idle';
    setPipelineStatus('PIPELINE COMPLETE', 'stat-active', 'Verification successful: Authenticated 96-byte header committed. In-memory keys purged with zero residual footprint.');
  } finally {
    isPipelineRunning = false;
  }
}

async function runDecryptPipelineTrace() {
  if (isPipelineRunning) return;
  isPipelineRunning = true;
  clearAllPipelineHighlights();

  try {
    setPipelineStatus('STEP 1/6', 'stat-active', 'Record Inspection: Reading 96-byte authenticated binary header; extracting salt (0x08), IV (0x18), and HMAC (0x38).');
    $('node-vaultmgr').classList.add('node-highlight');
    await sleep(800);

    setPipelineStatus('STEP 2/6', 'stat-active', 'Key Regeneration: PBKDF2 re-derives master key and HMAC key from user passphrase and extracted header salt.');
    $('node-kdf').classList.add('node-highlight');
    await sleep(900);

    setPipelineStatus('STEP 3/6', 'stat-active', 'Pre-Flight HMAC Authentication: Verifying SHA-256 HMAC in constant-time (CRYPTO_memcmp).');
    $('node-cli').classList.add('node-highlight');
    await sleep(900);

    setPipelineStatus('STEP 4/6', 'stat-active', 'Authentication Succeeded: HMAC tag verified. Acquiring kernel device and setting decrypt mode.');
    $('step-open').classList.add('step-active');
    $('node-kdev').classList.add('node-highlight');
    $('node-kmem').classList.add('node-highlight');
    appendKernelLog('ioctl SET_MODE: operational mode set to KVAULT_MODE_DECRYPT (1)');
    await sleep(900);

    setPipelineStatus('STEP 5/6', 'stat-active', 'Streaming Decryption: Kernel Crypto API decrypts 64 KiB blocks; PKCS#7 padding stripped using original_size field.');
    $('step-io-chunks').classList.add('step-active');
    $('node-cryptoapi').classList.add('node-highlight');
    $('node-scatterlist').classList.add('node-highlight');
    appendKernelLog('transform: Decryption complete, unpadded plaintext buffer restored');
    await sleep(1000);

    setPipelineStatus('STEP 6/6', 'stat-active', 'Atomic Restore: Plaintext recovered to target destination via AtomicFileWriter. Session key zeroed.');
    $('node-atomic').classList.add('node-highlight');
    $('step-close').classList.add('step-active');
    appendKernelLog('release: Driver released cleanly');
    await sleep(700);

    setPipelineStatus('RESTORE VERIFIED', 'stat-active', 'Plaintext successfully restored and authenticated. Zero data corruption detected.');
  } finally {
    isPipelineRunning = false;
  }
}

async function runCrashSimulationTrace() {
  if (isPipelineRunning) return;
  isPipelineRunning = true;
  clearAllPipelineHighlights();

  setPipelineStatus('FAULT INJECTION', 'stat-err', 'Simulating catastrophic power loss / SIGKILL during active 64 KiB chunk write...');
  $$('.arch-node').forEach(n => n.classList.add('node-fault'));
  await sleep(900);

  setPipelineStatus('RECOVERY PROTOCOL', 'stat-warn', 'Crash Safety Audit: Kernel invokes kvault_release(), calling memzero_explicit() to wipe RAM and unlocking gate.');
  $('node-kdev').classList.add('node-highlight');
  $('node-kmem').classList.add('node-highlight');
  $('telem-gate-val').textContent = 'UNLOCKED (0)';
  appendKernelLog('fault recovery: process terminated abnormally; memzero_explicit() executed in release()', 'log-err');
  await sleep(1000);

  setPipelineStatus('STORAGE INTEGRITY', 'stat-active', 'File System Verification: Partial write was isolated inside .tmp.<pid> file. Target file was never touched. Zero torn writes.');
  $('node-atomic').classList.add('node-highlight');
  $('node-storage').classList.add('node-highlight');
  await sleep(900);

  setPipelineStatus('INODE CONSISTENT', 'stat-active', 'AtomicFileWriter invariant holds: Either complete record commits via renameat2 or original file remains unchanged.');
  isPipelineRunning = false;
}

function initArchitectureControls() {
  const btnEnc = $('btn-flow-encrypt');
  const btnDec = $('btn-flow-decrypt');
  const btnCrash = $('btn-flow-crash');
  const btnReset = $('btn-flow-reset');

  if (btnEnc) btnEnc.addEventListener('click', runEncryptPipelineTrace);
  if (btnDec) btnDec.addEventListener('click', runDecryptPipelineTrace);
  if (btnCrash) btnCrash.addEventListener('click', runCrashSimulationTrace);
  if (btnReset) btnReset.addEventListener('click', () => {
    clearAllPipelineHighlights();
    setPipelineStatus('IDLE', '', 'Ready. Select an execution trace above to inspect real-time boundary transitions and memory isolation guarantees.');
  });
}

/* ==========================================================================
   5. KERNEL IOCTL TESTBED CONTROLLER
   ========================================================================== */

const IOCTL_DEFINITIONS = {
  KVAULT_IOCTL_GET_STATUS: {
    macro: 'KVAULT_IOCTL_GET_STATUS',
    code: '0x80186b05',
    dir: '_IOR',
    type: 'struct kvault_status_param',
    c_struct: `struct kvault_status_param {
    uint32_t is_key_set;          /* 1 if master key is loaded in kernel */
    uint32_t cipher_mode;         /* 0 = Encrypt, 1 = Decrypt */
    uint64_t bytes_transformed;   /* Lifetime session throughput in bytes */
    uint32_t driver_version;      /* Kernel driver protocol version (1) */
};`,
    fields: []
  },
  KVAULT_IOCTL_SET_KEY: {
    macro: 'KVAULT_IOCTL_SET_KEY',
    code: '0x40246b01',
    dir: '_IOW',
    type: 'struct kvault_key_param',
    c_struct: `struct kvault_key_param {
    uint8_t key[32];              /* 256-bit AES master key material */
    uint32_t key_len;             /* Must equal exactly 32 bytes */
};`,
    fields: [
      { name: 'key_hex', label: 'AES-256 Key Material (64 Hex Characters)', default: '8f4c29b1d70e5a31a9834cf20918bd44c2195f00e84b7261a34891cd0275ef9a' },
      { name: 'key_len', label: 'Key Length (Bytes)', default: '32', readonly: true }
    ]
  },
  KVAULT_IOCTL_SET_IV: {
    macro: 'KVAULT_IOCTL_SET_IV',
    code: '0x40146b03',
    dir: '_IOW',
    type: 'struct kvault_iv_param',
    c_struct: `struct kvault_iv_param {
    uint8_t iv[16];               /* 128-bit CBC Initialization Vector */
    uint32_t iv_len;              /* Must equal exactly 16 bytes */
};`,
    fields: [
      { name: 'iv_hex', label: 'Initialization Vector (32 Hex Characters)', default: '1f8b4e7203a9cd5491e70258b34c2190' },
      { name: 'iv_len', label: 'IV Length (Bytes)', default: '16', readonly: true }
    ]
  },
  KVAULT_IOCTL_SET_MODE: {
    macro: 'KVAULT_IOCTL_SET_MODE',
    code: '0x40046b04',
    dir: '_IOW',
    type: 'int',
    c_struct: `/* Direct scalar parameter */
enum kvault_cipher_mode {
    KVAULT_MODE_ENCRYPT = 0,
    KVAULT_MODE_DECRYPT = 1
};`,
    fields: [
      { name: 'mode_val', label: 'Cipher Mode (0=Encrypt, 1=Decrypt)', default: '0' }
    ]
  },
  KVAULT_IOCTL_TRANSFORM: {
    macro: 'KVAULT_IOCTL_TRANSFORM',
    code: '0xc0186b06',
    dir: '_IOWR',
    type: 'struct kvault_transform_param',
    c_struct: `struct kvault_transform_param {
    const uint8_t *src;           /* Pointer to user-space input buffer */
    uint8_t *dst;                 /* Pointer to user-space output buffer */
    uint32_t length;              /* Buffer length (must be multiple of 16) */
    uint32_t mode;                /* 0 = Encrypt, 1 = Decrypt */
};`,
    fields: [
      { name: 'buf_len', label: 'Buffer Length (Bytes, Multiple of 16)', default: '65536' },
      { name: 't_mode', label: 'Transform Mode (0=Encrypt, 1=Decrypt)', default: '0' }
    ]
  },
  KVAULT_IOCTL_FLUSH_KEY: {
    macro: 'KVAULT_IOCTL_FLUSH_KEY',
    code: '0x00006b02',
    dir: '_IO',
    type: 'void',
    c_struct: `/* No payload: immediately executes memzero_explicit() in kernel RAM */`,
    fields: []
  }
};

function renderIoctlParams() {
  const select = $('ioctl-select');
  const container = $('ioctl-param-container');
  const codeView = $('ioctl-struct-code');
  if (!select || !container || !codeView) return;

  const cmdKey = select.value;
  const def = IOCTL_DEFINITIONS[cmdKey];
  if (!def) return;

  codeView.textContent = def.c_struct;

  if (def.fields.length === 0) {
    container.innerHTML = `<p class="section-desc">Command <code>${def.macro}</code> does not require user input parameters.</p>`;
    return;
  }

  let html = '';
  def.fields.forEach(f => {
    html += `
      <div class="form-group">
        <label class="form-label" for="param-${f.name}">${f.label}:</label>
        <input type="text" class="form-input" id="param-${f.name}" value="${f.default}" ${f.readonly ? 'readonly' : ''}>
      </div>
    `;
  });
  container.innerHTML = html;
}

function updateDriverStateDisplay() {
  const stStatus = $('kstate-status');
  const stBusy = $('kstate-busy');
  const stKey = $('kstate-key');
  const stMode = $('kstate-mode');
  const stBytes = $('kstate-bytes');

  if (stStatus) stStatus.textContent = KernelDeviceState.loaded ? 'ONLINE (/dev/kvault)' : 'UNLOADED';
  if (stBusy) stBusy.textContent = `${KernelDeviceState.busy} (${KernelDeviceState.busy ? 'LOCKED' : 'UNLOCKED'})`;
  if (stKey) stKey.textContent = KernelDeviceState.is_key_set ? 'LOADED (256-bit AES)' : 'NOT LOADED';
  if (stMode) stMode.textContent = KernelDeviceState.cipher_mode === 0 ? 'ENCRYPT (0)' : 'DECRYPT (1)';
  if (stBytes) stBytes.textContent = formatBytes(KernelDeviceState.bytes_transformed);
}

function dispatchIoctlCall() {
  const select = $('ioctl-select');
  if (!select) return;
  const cmd = select.value;

  switch (cmd) {
    case 'KVAULT_IOCTL_GET_STATUS':
      appendKernelLog(`ioctl(KVAULT_IOCTL_GET_STATUS): returned is_key_set=${KernelDeviceState.is_key_set}, mode=${KernelDeviceState.cipher_mode}, bytes=${KernelDeviceState.bytes_transformed}`);
      break;

    case 'KVAULT_IOCTL_SET_KEY':
      KernelDeviceState.is_key_set = true;
      KernelDeviceState.active_key_hex = $('param-key_hex') ? $('param-key_hex').value : '8f...';
      appendKernelLog(`ioctl(KVAULT_IOCTL_SET_KEY): loaded 32 bytes into kzalloc context (crypto_skcipher_setkey OK)`);
      break;

    case 'KVAULT_IOCTL_SET_IV':
      KernelDeviceState.active_iv_hex = $('param-iv_hex') ? $('param-iv_hex').value : '1f...';
      appendKernelLog(`ioctl(KVAULT_IOCTL_SET_IV): synchronization vector set (16 bytes)`);
      break;

    case 'KVAULT_IOCTL_SET_MODE':
      const modeVal = $('param-mode_val') ? parseInt($('param-mode_val').value, 10) : 0;
      KernelDeviceState.cipher_mode = modeVal === 1 ? 1 : 0;
      appendKernelLog(`ioctl(KVAULT_IOCTL_SET_MODE): mode changed to ${KernelDeviceState.cipher_mode === 0 ? 'ENCRYPT' : 'DECRYPT'}`);
      break;

    case 'KVAULT_IOCTL_TRANSFORM':
      if (!KernelDeviceState.is_key_set) {
        appendKernelLog(`ioctl(KVAULT_IOCTL_TRANSFORM): -EINVAL - master key not configured`, 'log-err');
        return;
      }
      const bLen = $('param-buf_len') ? parseInt($('param-buf_len').value, 10) : 65536;
      KernelDeviceState.bytes_transformed += bLen;
      appendKernelLog(`ioctl(KVAULT_IOCTL_TRANSFORM): successfully processed ${bLen} bytes via scatterlist DMA`);
      break;

    case 'KVAULT_IOCTL_FLUSH_KEY':
      KernelDeviceState.is_key_set = false;
      KernelDeviceState.active_key_hex = null;
      appendKernelLog(`ioctl(KVAULT_IOCTL_FLUSH_KEY): memzero_explicit() wiped session key`);
      break;
  }

  updateDriverStateDisplay();
}

function initIoctlTestbed() {
  const select = $('ioctl-select');
  if (select) select.addEventListener('change', renderIoctlParams);

  const btnDispatch = $('btn-dispatch-ioctl');
  if (btnDispatch) btnDispatch.addEventListener('click', dispatchIoctlCall);

  const btnReset = $('btn-reset-driver');
  if (btnReset) btnReset.addEventListener('click', () => {
    KernelDeviceState.is_key_set = false;
    KernelDeviceState.bytes_transformed = 0;
    KernelDeviceState.cipher_mode = 0;
    KernelDeviceState.busy = 0;
    appendKernelLog(`driver reset: simulated reload of sec_crypto.ko; structures reinitialized`);
    updateDriverStateDisplay();
  });

  const btnClearLog = $('btn-clear-klog');
  if (btnClearLog) btnClearLog.addEventListener('click', () => {
    const klog = $('ioctl-klog');
    if (klog) klog.innerHTML = '';
  });

  renderIoctlParams();
  updateDriverStateDisplay();
}

/* ==========================================================================
   6. BINARY FRAME DISSECTOR & HEX INSPECTOR
   ========================================================================== */

const HEADER_OFFSET_MAP = [
  { start: 0x00, end: 0x03, name: 'magic', type: 'uint32_t', role: 'Magic Signature', desc: 'Identifies KernelVault file format. Must equal "KVLT" (0x4B564C54).' },
  { start: 0x04, end: 0x07, name: 'version', type: 'uint32_t', role: 'Format Version', desc: 'Binary format schema version (0x00000001). Guarantees forward compatibility.' },
  { start: 0x08, end: 0x17, name: 'salt', type: 'uint8_t[16]', role: 'PBKDF2 Salt', desc: '128-bit cryptographic salt generated from /dev/urandom for key derivation.' },
  { start: 0x18, end: 0x27, name: 'iv', type: 'uint8_t[16]', role: 'CBC Initial Vector', desc: '128-bit Initialization Vector for AES-256-CBC chaining.' },
  { start: 0x28, end: 0x2f, name: 'original_size', type: 'uint64_t', role: 'Plaintext Length', desc: 'Unpadded plaintext length in bytes. Required to remove PKCS#7 padding accurately.' },
  { start: 0x30, end: 0x37, name: 'payload_size', type: 'uint64_t', role: 'Ciphertext Length', desc: 'Total encrypted ciphertext stream length stored in 64 KiB blocks.' },
  { start: 0x38, end: 0x57, name: 'hmac', type: 'uint8_t[32]', role: 'HMAC-SHA256 Authenticator', desc: 'Constant-time verification tag. Validated before decryption starts.' },
  { start: 0x58, end: 0x5f, name: 'reserved', type: 'uint8_t[8]', role: '64-bit Alignment', desc: 'Zeroed alignment bytes to preserve 64-bit boundary alignment.' }
];

let activeSample = HEADER_SAMPLES.sample1;

function flattenHeader(sample) {
  const bytes = [];
  bytes.push(...sample.magic);
  bytes.push(...sample.version);
  bytes.push(...sample.salt);
  bytes.push(...sample.iv);
  bytes.push(...sample.orig_size);
  bytes.push(...sample.payload_size);
  bytes.push(...sample.hmac);
  bytes.push(...sample.reserved);
  return bytes;
}

function renderHexDump(sample) {
  const container = $('hex-dump-display');
  if (!container) return;

  const rawBytes = flattenHeader(sample);
  let html = '';

  for (let offset = 0; offset < rawBytes.length; offset += 16) {
    const lineBytes = rawBytes.slice(offset, offset + 16);
    const hexOffsetStr = '0x' + offset.toString(16).padStart(4, '0');

    let bytesHtml = '';
    let asciiStr = '';

    for (let i = 0; i < 16; i++) {
      const byteIdx = offset + i;
      if (byteIdx < rawBytes.length) {
        const b = lineBytes[i];
        const hexVal = b.toString(16).padStart(2, '0').toUpperCase();
        bytesHtml += `<span class="hex-b" data-idx="${byteIdx}">${hexVal}</span> `;
        asciiStr += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
      } else {
        bytesHtml += `   `;
      }
    }

    html += `
      <div class="hex-line">
        <span class="hex-offset">${hexOffsetStr}</span>
        <span class="hex-bytes">${bytesHtml}</span>
        <span class="hex-ascii">${asciiStr}</span>
      </div>
    `;
  }

  container.innerHTML = html;
  bindHexHoverEvents(rawBytes);
}

function bindHexHoverEvents(rawBytes) {
  const byteElements = $$('.hex-b');

  byteElements.forEach(el => {
    el.addEventListener('mouseenter', () => {
      const idx = parseInt(el.dataset.idx, 10);
      const fieldDef = HEADER_OFFSET_MAP.find(f => idx >= f.start && idx <= f.end);
      if (!fieldDef) return;

      // Highlight all bytes belonging to this field
      byteElements.forEach(b => {
        const bIdx = parseInt(b.dataset.idx, 10);
        if (bIdx >= fieldDef.start && bIdx <= fieldDef.end) {
          b.classList.add('highlight');
        } else {
          b.classList.remove('highlight');
        }
      });

      // Update Inspector Card
      $('insp-field-title').textContent = `${fieldDef.role} (${fieldDef.name})`;
      $('insp-member').textContent = `${fieldDef.type} ${fieldDef.name}`;
      $('insp-offset').textContent = `0x${fieldDef.start.toString(16).padStart(2, '0')} – 0x${fieldDef.end.toString(16).padStart(2, '0')} (${fieldDef.end - fieldDef.start + 1} Bytes)`;

      const fieldSlice = rawBytes.slice(fieldDef.start, fieldDef.end + 1);
      $('insp-hex').textContent = fieldSlice.map(b => '0x' + b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
      $('insp-role').textContent = fieldDef.desc;

      if (fieldDef.name === 'magic') {
        $('insp-rep').textContent = 'ASCII: "KVLT" (0x4B564C54)';
        $('insp-failure').textContent = 'Immediately returns -EINVAL on header load. No memory allocated.';
      } else if (fieldDef.name === 'version') {
        $('insp-rep').textContent = 'Integer: 1 (Schema v1)';
        $('insp-failure').textContent = 'Returns -EPROTONOSUPPORT if version != 1.';
      } else if (fieldDef.name === 'hmac') {
        $('insp-rep').textContent = '32-byte SHA-256 HMAC digest';
        $('insp-failure').textContent = 'Returns -EBADMSG: Constant-time authentication failed. File rejected.';
      } else if (fieldDef.name === 'original_size') {
        const sizeVal = fieldSlice[0] | (fieldSlice[1] << 8) | (fieldSlice[2] << 16);
        $('insp-rep').textContent = `${sizeVal.toLocaleString()} Bytes (${formatBytes(sizeVal)})`;
        $('insp-failure').textContent = 'Used for strict PKCS#7 boundary check.';
      } else {
        $('insp-rep').textContent = 'Binary Cryptographic Entropy';
        $('insp-failure').textContent = 'Causes cipher decryption failure.';
      }
    });
  });
}

function initBinaryDissector() {
  const btnSample1 = $('btn-hex-sample-1');
  const btnSample2 = $('btn-hex-sample-2');

  if (btnSample1 && btnSample2) {
    btnSample1.addEventListener('click', () => {
      btnSample1.classList.add('active');
      btnSample2.classList.remove('active');
      activeSample = HEADER_SAMPLES.sample1;
      renderHexDump(activeSample);
    });

    btnSample2.addEventListener('click', () => {
      btnSample2.classList.add('active');
      btnSample1.classList.remove('active');
      activeSample = HEADER_SAMPLES.sample2;
      renderHexDump(activeSample);
    });
  }

  renderHexDump(activeSample);
}

/* ==========================================================================
   7. CLI SANDBOX & POSIX TERMINAL
   ========================================================================== */

class VtTerminal {
  constructor(outputEl, inputEl) {
    this.output = outputEl;
    this.input = inputEl;
    this.history = [];
    this.historyIdx = -1;

    this.fs = {
      '/secure/vault': ['kernel_spec.pdf.kvlt', 'vault_backup.tar.gz.kvlt']
    };

    this.bindEvents();
  }

  bindEvents() {
    this.input.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        const cmd = this.input.value.trim();
        if (cmd) {
          this.history.unshift(cmd);
          this.historyIdx = -1;
          this.input.value = '';
          this.exec(cmd);
        }
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (this.historyIdx < this.history.length - 1) {
          this.historyIdx++;
          this.input.value = this.history[this.historyIdx];
        }
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (this.historyIdx > 0) {
          this.historyIdx--;
          this.input.value = this.history[this.historyIdx];
        } else {
          this.historyIdx = -1;
          this.input.value = '';
        }
      }
    });
  }

  printLine(html) {
    const row = document.createElement('div');
    row.className = 'vt-row';
    row.innerHTML = html;
    this.output.appendChild(row);
    this.output.scrollTop = this.output.scrollHeight;
  }

  printPrompt(cmd) {
    this.printLine(`<span class="vt-user">engineer@linux-workstation</span><span class="vt-colon">:</span><span class="vt-path">~/workspace</span><span class="vt-dollar">$</span> ${this.escapeHtml(cmd)}`);
  }

  clear() {
    this.output.innerHTML = '';
  }

  escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  async exec(fullCmd) {
    this.printPrompt(fullCmd);
    const args = fullCmd.split(/\s+/);
    const cmd = args[0];

    if (cmd === 'clear') {
      this.clear();
      return;
    }

    if (cmd === 'help') {
      this.printLine(`KernelVault (kvault) Terminal Sandbox Commands:
  kvault init     --vault &lt;path&gt;                    Initialize vault directory
  kvault encrypt  --in &lt;file&gt; --vault &lt;path&gt;       Encrypt plaintext into vault
  kvault decrypt  --file &lt;f&gt; --vault &lt;p&gt; --out &lt;o&gt; Decrypt and verify record
  kvault status   --vault &lt;path&gt;                    Audit vault files and integrity
  kvault wipe                                       Zero master key material in kernel
  dmesg | tail -n &lt;N&gt;                               Inspect kernel ring buffer
  ls -la &lt;dir&gt;                                     List filesystem directory
  simulate-crash                                    Test atomic commit recovery
  clear                                             Clear screen`);
      return;
    }

    if (cmd === 'ls') {
      const dir = args[1] || '/secure/vault';
      if (dir.includes('/secure/vault')) {
        this.printLine(`total 688
drwx------ 2 root root   4096 Oct  1 14:00 .
drwxr-xr-x 3 root root   4096 Oct  1 13:58 ..
-rw------- 1 root root 139360 Oct  1 14:02 kernel_spec.pdf.kvlt
-rw------- 1 root root 547760 Oct  1 14:05 vault_backup.tar.gz.kvlt`);
      } else {
        this.printLine(`drwxr-xr-x 4 engineer engineer 4096 Oct  1 14:00 .
-rw-r--r-- 1 engineer engineer 139344 Oct  1 13:50 kernel_spec.pdf
-rw-r--r-- 1 engineer engineer 547744 Oct  1 13:55 vault_backup.tar.gz`);
      }
      return;
    }

    if (cmd === 'dmesg') {
      this.printLine(`[   12.304101] sec_crypto: driver loaded, assigned major 243, minor 0
[   12.304122] sec_crypto: crypto_alloc_skcipher("cbc(aes)") initialized
[   12.304144] sec_crypto: atomic gate status: UNLOCKED (0)
[   45.109210] kvault[1024]: ioctl SET_KEY -> 256-bit key pinned in kzalloc RAM
[   45.110034] kvault[1024]: write 65536 bytes -> AES-256-CBC transformed
[   45.112998] kvault[1024]: close() -> memzero_explicit() wiped session key`);
      return;
    }

    if (cmd === 'simulate-crash') {
      this.printLine(`<span style="color:#ef4444;">[CRASH] Sending SIGKILL to active kvault process (PID 1024)...</span>`);
      await sleep(300);
      this.printLine(`[SYSTEM] Kernel invoking kvault_release(): memzero_explicit() cleared session key.`);
      this.printLine(`[ATOMIC] Inspected /secure/vault: Uncommitted temp file '.tmp.1024' removed.`);
      this.printLine(`<span style="color:#10b981;">[CONSISTENCY] Target record is completely untouched. Zero torn writes detected.</span>`);
      return;
    }

    if (cmd === 'kvault') {
      const sub = args[1];

      if (sub === 'init') {
        const vPath = this.getArgVal(args, '--vault') || '/secure/vault';
        this.printLine(`[kvault] Initializing vault directory at ${vPath} (mode 0700)...`);
        await sleep(200);
        this.printLine(`[kernel] /dev/kvault connection verified (Major: 243, Minor: 0)`);
        this.printLine(`<span style="color:#10b981;">SUCCESS: Secure vault initialized at ${vPath}.</span>`);
        return;
      }

      if (sub === 'encrypt') {
        const inFile = this.getArgVal(args, '--in') || 'data.bin';
        const vPath = this.getArgVal(args, '--vault') || '/secure/vault';
        this.printLine(`[kvault] Encrypting ${inFile} into ${vPath}...`);
        await sleep(300);
        this.printLine(`[kdf]    PBKDF2-HMAC-SHA256: 100,000 iterations completed.`);
        this.printLine(`[kernel] Master key injected via IOCTL; user-space buffer wiped with explicit_bzero().`);
        this.printLine(`[driver] Synchronous AES-256-CBC transform completed in 64 KiB chunks.`);
        this.printLine(`[atomic] fsync() writeback flush barrier passed.`);
        this.printLine(`[atomic] renameat2(RENAME_NOREPLACE) committed atomically.`);
        this.printLine(`<span style="color:#10b981;">SUCCESS: Created ${vPath}/${inFile}.kvlt (96-byte authenticated header attached).</span>`);
        return;
      }

      if (sub === 'decrypt') {
        const file = this.getArgVal(args, '--file') || 'kernel_spec.pdf';
        const key = this.getArgVal(args, '--key') || '';
        this.printLine(`[kvault] Verifying record ${file}...`);
        await sleep(350);

        if (key.includes('Wrong')) {
          this.printLine(`<span style="color:#ef4444;">ERROR: HMAC-SHA256 authentication mismatch (offset 0x38).</span>`);
          this.printLine(`<span style="color:#ef4444;">kvault: -EBADMSG (74): Bad message / Invalid key material. Decryption aborted before cipher execution.</span>`);
          return;
        }

        this.printLine(`[auth]   HMAC-SHA256 constant-time check: PASS.`);
        this.printLine(`[kernel] IOCTL transform AES-256-CBC decrypt: 139,360 bytes.`);
        this.printLine(`[pad]    PKCS#7 unpadding: 139,344 bytes plaintext recovered.`);
        this.printLine(`<span style="color:#10b981;">SUCCESS: Plaintext restored to destination file with verified integrity.</span>`);
        return;
      }

      if (sub === 'status') {
        const vPath = this.getArgVal(args, '--vault') || '/secure/vault';
        this.printLine(`Vault Status: ${vPath}
  Initialization : True (POSIX mode 0700)
  Driver Status  : Available (/dev/kvault, major=243)
  Lifetime IO    : 687,104 Bytes transformed
  Records (2):
    - kernel_spec.pdf.kvlt   [139,360 B] (HMAC: 4a8821d9b3... OK)
    - vault_backup.tar.gz.kvlt [547,760 B] (HMAC: 9c12fa4820... OK)
  Lock Status    : UNLOCKED (No active advisory locks)`);
        return;
      }

      if (sub === 'wipe') {
        this.printLine(`[kernel] Invoking KVAULT_IOCTL_FLUSH_KEY...`);
        KernelDeviceState.is_key_set = false;
        updateDriverStateDisplay();
        this.printLine(`<span style="color:#10b981;">SUCCESS: memzero_explicit() executed. Key memory purged from physical RAM.</span>`);
        return;
      }

      this.printLine(`kvault: unknown command '${sub}'. Type 'help' for usage.`);
      return;
    }

    this.printLine(`bash: command not found: ${cmd}. Type 'help' for reference.`);
  }

  getArgVal(args, flag) {
    const idx = args.indexOf(flag);
    if (idx !== -1 && args[idx + 1]) {
      return args[idx + 1].replace(/^'|'$/g, '').replace(/^"|"$/g, '');
    }
    return null;
  }
}

function initTerminal() {
  const outputEl = $('term-output');
  const inputEl = $('term-cli-input');
  if (!outputEl || !inputEl) return;

  const terminal = new VtTerminal(outputEl, inputEl);

  const btnClear = $('btn-clear-terminal');
  if (btnClear) btnClear.addEventListener('click', () => terminal.clear());

  $$('.preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const cmd = btn.dataset.run;
      if (cmd) {
        inputEl.focus();
        terminal.exec(cmd);
      }
    });
  });
}

/* ==========================================================================
   8. APPLICATION ENTRYPOINT
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initArchitectureControls();
  initIoctlTestbed();
  initBinaryDissector();
  initTerminal();
});

/* ==========================================================================
   8. VAULT OPERATIONS CONTROLLER (vault.html)
   ========================================================================== */

function initVaultOperations() {
  const encDropZone = $('enc-drop-zone');
  const encFileInput = $('enc-file-input');
  const encFileName = $('enc-file-name');
  const btnEncrypt = $('btn-encrypt-action');
  
  if (encDropZone && encFileInput) {
    // Click to select
    encDropZone.addEventListener('click', () => encFileInput.click());
    
    // Handle File Selection
    const handleFile = (file) => {
      encFileName.textContent = `Selected: ${file.name} (${formatBytes(file.size)})`;
      encFileName.dataset.filename = file.name;
      encFileName.dataset.filesize = file.size;
      encFileName.style.display = 'block';
      encDropZone.style.borderColor = 'var(--accent-primary)';
      encDropZone.style.background = 'var(--bg-surface-elev)';
    };

    encFileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) handleFile(e.target.files[0]);
    });

    // Drag and Drop Events
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      encDropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
      });
    });

    ['dragenter', 'dragover'].forEach(eventName => {
      encDropZone.addEventListener(eventName, () => {
        encDropZone.style.borderColor = 'var(--accent-primary)';
        encDropZone.style.background = 'var(--bg-surface-elev)';
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      encDropZone.addEventListener(eventName, () => {
        encDropZone.style.borderColor = 'var(--border-default)';
        encDropZone.style.background = 'var(--bg-surface)';
      });
    });

    encDropZone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      if (dt.files && dt.files.length > 0) {
        encFileInput.files = dt.files;
        handleFile(dt.files[0]);
      }
    });
  }
  
  if (btnEncrypt) {
    btnEncrypt.addEventListener('click', async () => {
      const pass = $('enc-password').value;
      if (!pass || (!encFileInput.files.length && !encFileName.textContent.includes('Selected'))) {
        alert('Please select a file and enter a master password.');
        return;
      }
      
      $('enc-progress-container').style.display = 'block';
      const pct = $('enc-pct');
      const bar = $('enc-progress-bar');
      const status = $('enc-status');
      
      status.textContent = 'Deriving Key (PBKDF2-HMAC-SHA256)...';
      status.style.color = 'var(--text-secondary)';
      bar.style.width = '10%'; pct.textContent = '10%';
      await sleep(800);
      
      status.textContent = 'Acquiring Kernel Lock /dev/kvault...';
      bar.style.width = '30%'; pct.textContent = '30%';
      await sleep(500);
      
      status.textContent = 'Encrypting chunks in kernel (AES-256-CBC)...';
      for(let i = 30; i <= 90; i+=10) {
        bar.style.width = i + '%'; pct.textContent = i + '%';
        await sleep(200);
      }
      
      status.textContent = 'Atomic Commit & Writeback (fsync)...';
      bar.style.width = '100%'; pct.textContent = '100%';
      await sleep(600);
      
      status.textContent = 'Successfully encrypted to vault!';
      status.style.color = 'var(--status-ok)';
      
      // Save it to the vault (simulate by adding to the select dropdown)
      const originalName = encFileName.dataset.filename || 'document.txt';
      const originalSize = encFileName.dataset.filesize || 1024;
      const vaultName = originalName + '.kvlt';
      
      // Update decrypt dropdown
      const selectBox = $('dec-file-select');
      if (selectBox) {
        const option = document.createElement('option');
        option.value = vaultName;
        // add 96 bytes for header + 16 for padding roughly
        const encSize = parseInt(originalSize) + 112; 
        option.text = `${vaultName} (${formatBytes(encSize)}) [NEW]`;
        option.selected = true;
        selectBox.appendChild(option);
      }

      // Simulate download (optional nice touch for UI proof)
      const blob = new Blob(["Simulated encrypted data..."], {type: "application/octet-stream"});
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = vaultName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      
      // Reset form
      setTimeout(() => {
        $('enc-password').value = '';
        if (encFileInput) encFileInput.value = '';
        encFileName.style.display = 'none';
        encDropZone.style.borderColor = 'var(--border-default)';
        encDropZone.style.background = 'var(--bg-surface)';
        setTimeout(() => {
           $('enc-progress-container').style.display = 'none';
           bar.style.width = '0%';
        }, 3000);
      }, 1000);
    });
  }
  
  const btnDecrypt = $('btn-decrypt-action');
  if (btnDecrypt) {
    btnDecrypt.addEventListener('click', async () => {
      const fileSelect = $('dec-file-select');
      const pass = $('dec-password').value;
      if (!pass || fileSelect.value === '') {
        alert('Please select an encrypted file and enter your password.');
        return;
      }
      
      $('dec-progress-container').style.display = 'block';
      const pct = $('dec-pct');
      const bar = $('dec-progress-bar');
      const status = $('dec-status');
      const actionText = $('dec-action-text');
      
      status.textContent = 'Loading binary header...';
      status.style.color = 'var(--text-secondary)';
      bar.style.background = 'var(--accent-primary)';
      bar.style.width = '20%'; pct.textContent = '20%';
      await sleep(600);
      
      actionText.textContent = 'Authenticating HMAC-SHA256...';
      status.textContent = 'Constant-time verification running...';
      bar.style.width = '50%'; pct.textContent = '50%';
      await sleep(800);
      
      if (pass !== 'MasterKey2026' && pass !== 'MasterSecret#2026') {
         if (pass.toLowerCase() === 'wrong') {
             bar.style.background = 'var(--status-err)';
             status.textContent = 'ERROR: HMAC-SHA256 Signature Mismatch! Tampering detected or wrong password.';
             status.style.color = 'var(--status-err)';
             return;
         }
      }
      
      actionText.textContent = 'Decrypting...';
      status.textContent = 'Decrypting chunks via Kernel Crypto API...';
      for(let i = 50; i <= 90; i+=10) {
        bar.style.width = i + '%'; pct.textContent = i + '%';
        await sleep(150);
      }
      
      bar.style.width = '100%'; pct.textContent = '100%';
      status.textContent = 'Successfully decrypted and extracted!';
      status.style.color = 'var(--status-ok)';
      bar.style.background = 'var(--status-ok)';
      
      // Simulate original file extraction download
      let origName = fileSelect.value.replace('.kvlt', '');
      const blob = new Blob(["Simulated decrypted data..."], {type: "application/octet-stream"});
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = origName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      setTimeout(() => {
        $('dec-password').value = '';
        fileSelect.selectedIndex = 0;
        setTimeout(() => {
           $('dec-progress-container').style.display = 'none';
           bar.style.width = '0%';
        }, 3000);
      }, 1000);
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
    if (typeof initVaultOperations === "function") {
        initVaultOperations();
    }
});
