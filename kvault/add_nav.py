import glob
import re
import os

html_files = glob.glob('web/*.html')

new_nav_item = '''
    <a href="vault.html" class="nav-tab {c_vault}">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
      <span>Vault Operations</span>
    </a>
'''

for file in html_files:
    with open(file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    if 'vault.html' in content:
        continue
        
    pattern = r'(<a href="terminal\.html".*?</a>)'
    # Give the active class only if it's the vault.html page (which we haven't created yet, but we will)
    # The current files don't have c_vault in them, so we just replace {c_vault} with empty string for existing files
    replacement = new_nav_item.replace('{c_vault}', '') + r'\1'
    
    new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
    
    with open(file, 'w', encoding='utf-8') as f:
        f.write(new_content)

print('Updated navigation in all HTML files.')

# Also generate vault.html based on index.html
with open('web/index.html', 'r', encoding='utf-8') as f:
    idx_content = f.read()

# Replace active class
v_content = idx_content.replace('class="nav-tab active"', 'class="nav-tab"')
v_content = v_content.replace('href="vault.html" class="nav-tab "', 'href="vault.html" class="nav-tab active"')

# We will inject the actual vault content in place of the dashboard content
vault_body = '''
    <div class="panel-section" style="max-width: 900px; margin: 0 auto;">
      <h2 class="section-title" style="font-size: 1.5rem; margin-bottom: 8px;">Vault Operations</h2>
      <p class="section-desc" style="margin-bottom: 32px;">Securely encrypt or decrypt your files using the KernelVault engine.</p>
      
      <div class="split-pane">
        <!-- Encrypt Column -->
        <div class="pane-column">
          <div class="stride-card" style="padding: 24px;">
            <h3 class="stride-title" style="display: flex; align-items: center; gap: 8px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 16px; margin-bottom: 24px;">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="status-ok"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              Encrypt File
            </h3>
            
            <div class="form-group">
              <label class="form-label">Select File to Encrypt</label>
              <div class="file-drop-zone" id="enc-drop-zone" style="border: 2px dashed var(--border-default); border-radius: var(--radius-md); padding: 32px 20px; text-align: center; cursor: pointer; transition: all 0.2s; background: var(--bg-surface);">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--text-muted); margin-bottom: 12px;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                <div style="font-size: 0.9rem; color: var(--text-secondary); font-weight: 500;">Click or drag file here</div>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">Supports any file format</div>
              </div>
              <input type="file" id="enc-file-input" style="display: none;">
              <div id="enc-file-name" style="margin-top: 8px; font-size: 0.85rem; color: var(--accent-primary); font-weight: 600; text-align: center; display: none;"></div>
            </div>
            
            <div class="form-group">
              <label class="form-label">Master Password</label>
              <input type="password" id="enc-password" class="form-input" placeholder="Enter highly secure password...">
            </div>
            
            <button class="btn btn-primary" id="btn-encrypt-action" style="width: 100%; justify-content: center; padding: 12px; font-size: 1rem;">
              Encrypt & Store in Vault
            </button>
            
            <div id="enc-progress-container" style="margin-top: 20px; display: none;">
              <div style="display: flex; justify-content: space-between; font-size: 0.8rem; font-family: var(--font-mono); color: var(--text-secondary); margin-bottom: 8px;">
                <span>Encrypting...</span><span id="enc-pct">0%</span>
              </div>
              <div style="height: 6px; background: var(--border-subtle); border-radius: 99px; overflow: hidden;">
                <div id="enc-progress-bar" style="height: 100%; width: 0%; background: var(--accent-primary); transition: width 0.1s linear;"></div>
              </div>
              <div id="enc-status" style="margin-top: 12px; font-size: 0.8rem; color: var(--status-ok); font-weight: 500; text-align: center;"></div>
            </div>
          </div>
        </div>

        <!-- Decrypt Column -->
        <div class="pane-column">
          <div class="stride-card" style="padding: 24px;">
            <h3 class="stride-title" style="display: flex; align-items: center; gap: 8px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 16px; margin-bottom: 24px;">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="status-warn"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>
              Decrypt File
            </h3>
            
            <div class="form-group">
              <label class="form-label">Select Vault File (.kvlt)</label>
              <select id="dec-file-select" class="form-select">
                <option value="" disabled selected>Select an encrypted file...</option>
                <option value="kernel_spec.pdf.kvlt">kernel_spec.pdf.kvlt (139 KiB)</option>
                <option value="vault_backup.tar.gz.kvlt">vault_backup.tar.gz.kvlt (547 KiB)</option>
              </select>
            </div>
            
            <div class="form-group">
              <label class="form-label">Master Password</label>
              <input type="password" id="dec-password" class="form-input" placeholder="Enter your password...">
            </div>
            
            <button class="btn btn-secondary" id="btn-decrypt-action" style="width: 100%; justify-content: center; padding: 12px; font-size: 1rem; color: var(--text-primary); border: 1px solid var(--border-default);">
              Decrypt & Extract
            </button>
            
            <div id="dec-progress-container" style="margin-top: 20px; display: none;">
              <div style="display: flex; justify-content: space-between; font-size: 0.8rem; font-family: var(--font-mono); color: var(--text-secondary); margin-bottom: 8px;">
                <span id="dec-action-text">Verifying HMAC...</span><span id="dec-pct">0%</span>
              </div>
              <div style="height: 6px; background: var(--border-subtle); border-radius: 99px; overflow: hidden;">
                <div id="dec-progress-bar" style="height: 100%; width: 0%; background: var(--status-ok); transition: width 0.1s linear;"></div>
              </div>
              <div id="dec-status" style="margin-top: 12px; font-size: 0.8rem; font-weight: 500; text-align: center;"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
'''

# Replace the dashboard content with the vault body
pattern = r'<div class="panel-section">.*?</div>\s*</div>'
final_content = re.sub(pattern, vault_body, v_content, flags=re.DOTALL)

with open('web/vault.html', 'w', encoding='utf-8') as f:
    f.write(final_content)

print('vault.html generated successfully.')
