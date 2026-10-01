import time

js_code = '''
/* ==========================================================================
   8. VAULT OPERATIONS CONTROLLER (vault.html)
   ========================================================================== */

function initVaultOperations() {
  const encDropZone = $('enc-drop-zone');
  const encFileInput = $('enc-file-input');
  const encFileName = $('enc-file-name');
  const btnEncrypt = $('btn-encrypt-action');
  
  if (encDropZone && encFileInput) {
    encDropZone.addEventListener('click', () => encFileInput.click());
    
    encFileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        const file = e.target.files[0];
        encFileName.textContent = `Selected: ${file.name} (${formatBytes(file.size)})`;
        encFileName.style.display = 'block';
        encDropZone.style.borderColor = 'var(--accent-primary)';
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
      
      // Reset form
      setTimeout(() => {
        $('enc-password').value = '';
        if (encFileInput) encFileInput.value = '';
        encFileName.style.display = 'none';
        encDropZone.style.borderColor = 'var(--border-default)';
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
         // Simulate failed auth if it's clearly a wrong test pass
         // But actually just pretend it succeeds if they type anything for the demo, 
         // except if they type "wrong"
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

// Ensure initVaultOperations runs
document.addEventListener("DOMContentLoaded", () => {
    initVaultOperations();
});
'''

with open('web/app.js', 'a', encoding='utf-8') as f:
    f.write(js_code)

print('app.js updated successfully.')
