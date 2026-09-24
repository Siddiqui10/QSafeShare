/**
 * QSafeShare - Post-Quantum Key Vault Controller
 */

window.VaultModule = {
  currentVault: null,

  async loadVault() {
    const container = document.getElementById("vaultContentContainer");
    if (!container) return;
    container.innerHTML = `<div style="text-align:center; padding:2rem;">Loading Post-Quantum Key Vault...</div>`;

    try {
      const vault = await apiRequest("/api/auth/vault");
      this.currentVault = vault;

      container.innerHTML = `
        <div class="benchmark-grid" style="grid-template-columns: repeat(4, 1fr); margin-bottom:1.5rem;">
          <div class="metric-card">
            <div class="metric-label">Algorithm Standard</div>
            <div class="metric-value" style="font-size:1.15rem; color:var(--pqc-cyan);">NIST FIPS 203</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Security Category</div>
            <div class="metric-value" style="font-size:1.15rem; color:var(--pqc-purple);">Level 3 (AES-192)</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Public Key Size</div>
            <div class="metric-value" style="font-size:1.15rem;">${vault.public_key_bytes_len} bytes</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Ciphertext Size</div>
            <div class="metric-value" style="font-size:1.15rem;">${vault.ciphertext_bytes_len} bytes</div>
          </div>
        </div>

        <div style="margin-bottom:1.5rem;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
            <label style="font-size:0.8rem; font-weight:600; text-transform:uppercase; color:var(--text-dim);">
              ML-KEM Public Key (SubjectPublicKeyInfo PEM) — Distributed to System
            </label>
            <button class="btn btn-secondary btn-sm" onclick="VaultModule.downloadKey('public')">📥 Download Public Key</button>
          </div>
          <div class="key-box">${escapeHtml(vault.public_key_pem)}</div>
        </div>

        <div style="margin-bottom:1.5rem;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
            <label style="font-size:0.8rem; font-weight:600; text-transform:uppercase; color:var(--text-dim);">
              ML-KEM Private Key (PKCS8 PEM) — Client-Side Decapsulation Secret
            </label>
            <button class="btn btn-secondary btn-sm" onclick="VaultModule.downloadKey('private')">📥 Backup Private Key</button>
          </div>
          <div class="key-box" style="color:#fb7185;">${escapeHtml(vault.private_key_pem)}</div>
        </div>

        <div style="background:rgba(6, 182, 212, 0.05); border:1px solid rgba(6, 182, 212, 0.2); border-radius:var(--radius-md); padding:1rem;">
          <h4 style="font-size:0.9rem; color:var(--pqc-cyan); margin-bottom:0.4rem;">🛡️ Post-Quantum Guarantee</h4>
          <p style="font-size:0.82rem; color:var(--text-muted); line-height:1.4;">
            Unlike RSA and ECDH which rely on integer factorization or discrete logarithms (trivially solved by Shor's algorithm on a quantum computer),
            <strong>ML-KEM (Module Learning with Errors)</strong> relies on high-dimensional module lattice hardness problems, which have no known efficient polynomial-time quantum algorithm.
          </p>
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div style="color:var(--accent-rose); padding:1.5rem; text-align:center;">Failed to load vault: ${err.message}</div>`;
    }
  },

  downloadKey(type) {
    if (!this.currentVault) return;
    const content = type === "public" ? this.currentVault.public_key_pem : this.currentVault.private_key_pem;
    const filename = `${this.currentVault.username}_mlkem_${type}_key.pem`;
    const blob = new Blob([content], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  },
};
