import re

html = open('web/index.html', 'r', encoding='utf-8').read()

head_match = re.search(r'(<!DOCTYPE html>.*?</header>)', html, re.DOTALL)
footer_match = re.search(r'(</main>.*?</html>)', html, re.DOTALL)

head = head_match.group(1)
footer = footer_match.group(1)

# Extract tabs
tabs = {}
for i in range(1, 7):
    pattern = rf'(<!-- =+[\s\n]+TAB {i}:.*?role=\"tabpanel\">)(.*?)(?=<!-- =+[\s\n]+TAB \d|$|</main>)'
    match = re.search(pattern, html, re.DOTALL)
    if match:
        content = match.group(2)
        # Remove the closing div of tab-pane if it's the last thing
        content = re.sub(r'</div>\s*$', '', content).strip()
        tabs[i] = content

nav_template = '''
  <nav class="nav-tabs" role="navigation">
    <a href="index.html" class="nav-tab {c_idx}">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M9 21V9"/></svg>
      <span>Dashboard</span>
    </a>
    <a href="architecture.html" class="nav-tab {c_arch}">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
      <span>Architecture</span>
    </a>
    <a href="ioctl.html" class="nav-tab {c_ioctl}">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
      <span>Kernel IOCTL</span>
    </a>
    <a href="dissector.html" class="nav-tab {c_diss}">
      <svg width="16" height="16" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z\"/><polyline points=\"14 2 14 8 20 8\"/><line x1=\"16\" y1=\"13\" x2=\"8\" y2=\"13\"/><line x1=\"16\" y1=\"17\" x2=\"8\" y2=\"17\"/><polyline points=\"10 9 9 9 8 9\"/></svg>
      <span>Frame Dissector</span>
    </a>
    <a href="terminal.html" class="nav-tab {c_term}">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 7 4 4 20 4 20 7"/><line x1="9" y1="20" x2="15" y2="20"/><line x1="12" y1="4" x2="12" y2="20"/></svg>
      <span>CLI Sandbox</span>
    </a>
    <a href="security.html" class="nav-tab {c_sec}">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      <span>Threat Model</span>
    </a>
    <a href="manual.html" class="nav-tab {c_man}">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>
      <span>Manual</span>
    </a>
  </nav>
  <main class="app-body">
'''

dashboard_content = '''
    <div class="panel-section">
      <h2 class="section-title" style="font-size: 1.8rem; margin-bottom: 10px;">Welcome to KernelVault</h2>
      <p class="section-desc" style="font-size: 1rem;">A highly secure, Linux kernel-assisted cryptographic storage engine.</p>
      
      <div class="arch-split-grid" style="margin-top: 30px; grid-template-columns: 1fr 1fr; gap: 20px;">
        <div class="stride-card" style="padding: 24px;">
          <h3 class="stride-title" style="margin-bottom: 12px;">Why KernelVault?</h3>
          <p class="stride-prop" style="line-height: 1.6; color: var(--text-secondary);">KernelVault protects your sensitive files by performing all encryption inside a secure, non-swappable kernel enclave. This prevents malware, debuggers, and memory scrapers from ever seeing your master password in regular application memory.</p>
        </div>
        <div class="stride-card" style="padding: 24px;">
          <h3 class="stride-title" style="margin-bottom: 12px;">Crash Safety</h3>
          <p class="stride-prop" style="line-height: 1.6; color: var(--text-secondary);">Designed for the real world. If the power fails while you are saving a file, KernelVault guarantees your original file will never be corrupted. We use a three-phase atomic commit system to ensure 100% data integrity.</p>
        </div>
      </div>

      <h3 class="subsection-title" style="margin-top: 40px; font-size: 1.2rem;">Explore the Engineering Console</h3>
      <div class="arch-split-grid" style="margin-top: 20px; grid-template-columns: 1fr 1fr 1fr; gap: 15px;">
        <a href="architecture.html" class="stride-card" style="text-decoration: none; display: block; transition: border-color 0.2s;">
          <h3 class="stride-title">System Architecture &rarr;</h3>
          <p class="prop-value" style="margin-top: 5px; color: var(--text-muted);">Trace the encryption flow step-by-step.</p>
        </a>
        <a href="terminal.html" class="stride-card" style="text-decoration: none; display: block; transition: border-color 0.2s;">
          <h3 class="stride-title">CLI Sandbox &rarr;</h3>
          <p class="prop-value" style="margin-top: 5px; color: var(--text-muted);">Try out commands in the web terminal.</p>
        </a>
        <a href="manual.html" class="stride-card" style="text-decoration: none; display: block; transition: border-color 0.2s;">
          <h3 class="stride-title">Documentation &rarr;</h3>
          <p class="prop-value" style="margin-top: 5px; color: var(--text-muted);">Read the full technical specification.</p>
        </a>
      </div>
    </div>
'''

pages = {
    'index.html': {'c': dashboard_content, 'nav': 'c_idx'},
    'architecture.html': {'c': tabs[1], 'nav': 'c_arch'},
    'ioctl.html': {'c': tabs[2], 'nav': 'c_ioctl'},
    'dissector.html': {'c': tabs[3], 'nav': 'c_diss'},
    'terminal.html': {'c': tabs[4], 'nav': 'c_term'},
    'security.html': {'c': tabs[5], 'nav': 'c_sec'},
    'manual.html': {'c': tabs[6], 'nav': 'c_man'},
}

for filename, data in pages.items():
    nav = nav_template.format(**{k: 'active' if k == data['nav'] else '' for k in ['c_idx', 'c_arch', 'c_ioctl', 'c_diss', 'c_term', 'c_sec', 'c_man']})
    full_html = head + '\n' + nav + '\n<div class="tab-pane active" role="tabpanel">\n' + data['c'] + '\n</div>\n' + footer
    with open('web/' + filename, 'w', encoding='utf-8') as f:
        f.write(full_html)

print('Pages generated successfully.')
