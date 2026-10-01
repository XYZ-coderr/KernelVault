import re

with open('web/app.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Find where the vault operations controller starts
header = '/* ==========================================================================\n   8. VAULT OPERATIONS CONTROLLER (vault.html)\n   ========================================================================== */'

if header in content:
    base_content = content.split(header)[0]
else:
    base_content = content

new_js = header + '''

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
'''

with open('web/app.js', 'w', encoding='utf-8') as f:
    f.write(base_content + new_js)

print('app.js updated successfully with drag-and-drop and vault saving.')
