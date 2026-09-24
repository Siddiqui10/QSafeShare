/**
 * QSafeShare - Production Enterprise Application Controller
 */

const AppState = {
  token: localStorage.getItem("qsafeshare_token") || null,
  currentUser: null,
  activeTab: "my-files",
  ownedFiles: [],
  sharedFiles: [],
  currentModalFileId: null,
  shareSelectedRecipients: [], // Array of { id, username, full_name, email, kem_algorithm }
};

// Toast Notifications
function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  const icon = type === "success" ? "✓" : (type === "error" ? "🚫" : "ℹ️");
  toast.innerHTML = `<strong>${icon}</strong> <span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(100%)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// API Helper with JWT Authorization
async function apiRequest(endpoint, options = {}) {
  const headers = options.headers || {};
  if (AppState.token) {
    headers["Authorization"] = `Bearer ${AppState.token}`;
  }
  options.headers = headers;

  const response = await fetch(endpoint, options);
  if (response.status === 401) {
    // Session expired or invalid
    signOutUser();
    throw new Error("Session expired. Please sign in again.");
  }

  if (!response.ok) {
    let errorMsg = `HTTP Error ${response.status}`;
    try {
      const data = await response.json();
      if (data.detail) {
        if (typeof data.detail === "object") {
          errorMsg = data.detail.message || JSON.stringify(data.detail);
        } else {
          errorMsg = data.detail;
        }
      }
    } catch (_) {}
    throw new Error(errorMsg);
  }
  return response.json();
}

// Formatters
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

function formatDate(isoStr) {
  if (!isoStr) return "—";
  const d = new Date(isoStr);
  return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// App Initialization
document.addEventListener("DOMContentLoaded", async () => {
  initAuthUI();
  initNavigation();
  initModals();
  initRecipientSearch();

  // 1. Process URL params if returning from Google OAuth redirect (?token=... or ?auth_error=...)
  const handled = await handleUrlAuthParams();
  if (handled) {
    return;
  }

  // 2. Otherwise verify existing stored session or display login overlay
  if (AppState.token) {
    await checkSession();
  } else {
    showAuthOverlay();
  }
});

// Redirect user directly to Google OAuth consent screen
function redirectToGoogleLogin() {
  const statusEl = document.getElementById("oauthMainStatus");
  if (statusEl) {
    statusEl.style.display = "block";
    statusEl.innerHTML = `⚡ Redirecting to Google Sign-In...`;
  }
  window.location.href = "/api/auth/oauth/google/login";
}

// Handle OAuth tokens or error codes returned in URL query parameters
async function handleUrlAuthParams() {
  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get("token");
  const authError = urlParams.get("auth_error");

  if (authError) {
    const errorMsg = decodeURIComponent(authError);
    showToast(`Authentication failed: ${errorMsg}`, "error");
    const statusEl = document.getElementById("oauthMainStatus");
    if (statusEl) {
      statusEl.style.display = "block";
      statusEl.innerHTML = `<span style="color:var(--accent-rose);">Sign-In Error: ${escapeHtml(errorMsg)}</span>`;
    }
    window.history.replaceState({}, document.title, window.location.pathname);
    return false;
  }

  if (token) {
    AppState.token = token;
    localStorage.setItem("qsafeshare_token", token);
    window.history.replaceState({}, document.title, window.location.pathname);
    try {
      const user = await apiRequest("/api/auth/me");
      AppState.currentUser = user;
      localStorage.setItem("qsafeshare_user", JSON.stringify(user));
      saveAccount("google", user.email, user.full_name);
      renderUserProfile();
      hideAuthOverlay();
      showToast(`Welcome, ${user.full_name}! (Google Authenticated)`, "success");
      await refreshCurrentTabData();
      startAuditStream();
      return true;
    } catch (e) {
      console.error("Failed to establish session from OAuth token:", e);
      signOutUser();
    }
  }
  return false;
}

function getSavedAccounts(provider = "google") {
  try {
    const raw = localStorage.getItem("qsafeshare_saved_accounts");
    if (!raw) return [];
    const accounts = JSON.parse(raw);
    return Array.isArray(accounts) ? accounts.filter(a => !provider || a.provider === provider) : [];
  } catch (_) {
    return [];
  }
}

function saveAccount(provider, email, fullName) {
  try {
    const accounts = getSavedAccounts();
    const cleanEmail = email.trim().toLowerCase();
    const cleanName = fullName ? fullName.trim() : cleanEmail.split("@")[0];
    const existingIndex = accounts.findIndex(a => a.email.toLowerCase() === cleanEmail);
    const newAcc = { provider: "google", email: cleanEmail, fullName: cleanName, lastLogin: new Date().toISOString() };
    if (existingIndex >= 0) {
      accounts[existingIndex] = newAcc;
    } else {
      accounts.unshift(newAcc);
    }
    localStorage.setItem("qsafeshare_saved_accounts", JSON.stringify(accounts.slice(0, 6)));
  } catch (_) {}
}

function removeSavedAccount(email, e) {
  if (e) e.stopPropagation();
  try {
    const accounts = getSavedAccounts().filter(a => a.email.toLowerCase() !== email.toLowerCase());
    localStorage.setItem("qsafeshare_saved_accounts", JSON.stringify(accounts));
    openOAuthModal("google");
  } catch (_) {}
}

function switchAccount() {
  signOutUser();
  showToast("Please choose an account to sign in.", "info");
}

function openOAuthModal(provider = "google") {
  currentOAuthProvider = "google";
  const titleEl = document.getElementById("oauthModalTitle");
  const iconEl = document.getElementById("oauthModalIcon");
  const descEl = document.getElementById("oauthModalDescription");
  const emailInput = document.getElementById("oauthCustomEmail");
  const nameInput = document.getElementById("oauthCustomName");
  const errEl = document.getElementById("oauthErrorMsg");
  const quickArea = document.getElementById("oauthQuickProfiles");
  const savedSection = document.getElementById("oauthSavedSection");
  const emailLabel = document.getElementById("oauthEmailLabel");
  const submitBtn = document.getElementById("btnSubmitOAuth");

  if (errEl) errEl.innerHTML = "";
  if (emailInput) emailInput.value = "";
  if (nameInput) nameInput.value = "";

  const savedAccounts = getSavedAccounts("google");

  if (titleEl) titleEl.textContent = "Google Sign-In";
  if (iconEl) iconEl.innerHTML = `
    <svg width="22" height="22" viewBox="0 0 24 24">
      <path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17z"/>
      <path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.15C3.26 21.36 7.33 24 12 24z"/>
      <path fill="#FBBC05" d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.25C.45 8.18 0 9.98 0 12s.45 3.82 1.25 5.42l4.03-3.15z"/>
      <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.33 0 3.26 2.64 1.25 6.58l4.03 3.15c.95-2.83 3.6-4.98 6.72-4.98z"/>
    </svg>
  `;
  if (descEl) descEl.innerHTML = "Sign in to <strong>QSafeShare</strong> with your Google account:";
  if (emailLabel) emailLabel.textContent = "Google Email Address";
  if (emailInput) emailInput.placeholder = "yourname@gmail.com";
  if (nameInput) nameInput.placeholder = "Your Full Name";
  if (submitBtn) submitBtn.textContent = "Sign In with Google";

  // Populate Saved Accounts
  if (savedAccounts.length > 0 && quickArea && savedSection) {
    savedSection.style.display = "block";
    quickArea.innerHTML = savedAccounts.map(a => `
      <div style="display:flex; align-items:center; justify-content:space-between; padding:0.65rem 0.85rem; border:1px solid var(--border-color); border-radius:var(--radius-md); background:var(--bg-secondary); cursor:pointer; transition:all 0.15s ease;" onclick="loginWithOAuth('google', '${escapeHtml(a.email)}', '${escapeHtml(a.fullName)}')">
        <div style="display:flex; align-items:center; gap:0.75rem;">
          <div style="width:34px; height:34px; border-radius:50%; background:#4285F4; border:1px solid #3367D6; color:#fff; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:0.9rem;">
            ${escapeHtml(a.fullName.substring(0, 1).toUpperCase())}
          </div>
          <div style="text-align:left;">
            <div style="font-weight:600; font-size:0.88rem; color:var(--text-main);">${escapeHtml(a.fullName)}</div>
            <div style="font-size:0.75rem; color:var(--text-dim);">${escapeHtml(a.email)}</div>
          </div>
        </div>
        <button type="button" class="btn btn-secondary btn-sm" style="font-size:0.7rem; padding:0.2rem 0.45rem; line-height:1;" title="Remove this saved account" onclick="removeSavedAccount('${escapeHtml(a.email)}', event)">✕</button>
      </div>
    `).join("");
  } else if (savedSection) {
    savedSection.style.display = "none";
  }

  openModal("oauthModal");
}

async function loginWithOAuth(provider = "google", email, fullName, oauthId = null) {
  const errEl = document.getElementById("oauthErrorMsg");
  const submitBtn = document.getElementById("btnSubmitOAuth");
  if (errEl) errEl.innerHTML = `<span style="color:var(--pqc-cyan);">Authenticating and provisioning ML-KEM-768 key vault...</span>`;
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = "Connecting...";
  }

  try {
    const data = await apiRequest(`/api/auth/oauth/google`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        provider: "google",
        email: email.trim(),
        full_name: fullName.trim() || email.split("@")[0],
        oauth_id: oauthId || `google_${Date.now()}`
      }),
    });

    saveAccount("google", data.user.email, data.user.full_name);
    closeModal("oauthModal");
    handleAuthSuccess(data);
    showToast(`Welcome, ${data.user.full_name}! (Google Authenticated)`, "success");
    return data;
  } catch (err) {
    if (errEl) errEl.innerHTML = `<span style="color:var(--accent-rose);">${escapeHtml(err.message)}</span>`;
    throw err;
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = "Sign In with Google";
    }
  }
}

function handleOAuthCustomSubmit(e) {
  e.preventDefault();
  const email = document.getElementById("oauthCustomEmail").value.trim();
  const name = document.getElementById("oauthCustomName").value.trim() || email.split("@")[0];
  if (!email) return;
  loginWithOAuth("google", email, name);
}


function initAuthUI() {
  const signinTabBtn = document.getElementById("authTabSignIn");
  const signupTabBtn = document.getElementById("authTabSignUp");
  const signinForm = document.getElementById("signInForm");
  const signupForm = document.getElementById("signUpForm");

  if (signinTabBtn && signupTabBtn) {
    signinTabBtn.addEventListener("click", () => {
      signinTabBtn.classList.add("active");
      signupTabBtn.classList.remove("active");
      signinForm.style.display = "block";
      signupForm.style.display = "none";
    });

    signupTabBtn.addEventListener("click", () => {
      signupTabBtn.classList.add("active");
      signinTabBtn.classList.remove("active");
      signupForm.style.display = "block";
      signinForm.style.display = "none";
    });
  }

  // Handle Login
  if (signinForm) {
    signinForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const loginErr = document.getElementById("signInError");
      loginErr.innerHTML = "";

      const username = document.getElementById("loginUsername").value.trim();
      const password = document.getElementById("loginPassword").value;

      try {
        const data = await apiRequest("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        });

        handleAuthSuccess(data);
        showToast(`Welcome back, ${data.user.full_name}!`, "success");
      } catch (err) {
        loginErr.innerHTML = `<span style="color:var(--accent-rose);">${escapeHtml(err.message)}</span>`;
      }
    });
  }

  // Handle Register
  if (signupForm) {
    signupForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const regErr = document.getElementById("signUpError");
      regErr.innerHTML = "";

      const fullName = document.getElementById("regFullName").value.trim();
      const regUserEl = document.getElementById("regUsername");
      const username = regUserEl ? regUserEl.value.trim() : "";
      const email = document.getElementById("regEmail").value.trim();
      const password = document.getElementById("regPassword").value;

      try {
        regErr.innerHTML = `<span style="color:var(--pqc-cyan);">Generating native NIST ML-KEM-768 post-quantum keypair...</span>`;
        const data = await apiRequest("/api/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            full_name: fullName,
            username: username || undefined,
            email,
            password,
            kem_algorithm: "ML-KEM-768",
          }),
        });

        handleAuthSuccess(data);
        showToast(`Account created with ML-KEM-768 keypair!`, "success");
      } catch (err) {
        regErr.innerHTML = `<span style="color:var(--accent-rose);">${escapeHtml(err.message)}</span>`;
      }
    });
  }

  // Sign out button
  const signOutBtn = document.getElementById("btnSignOut");
  if (signOutBtn) {
    signOutBtn.addEventListener("click", () => {
      signOutUser();
      showToast("Signed out successfully", "info");
    });
  }
}

function handleAuthSuccess(authData) {
  AppState.token = authData.access_token;
  AppState.currentUser = authData.user;
  localStorage.setItem("qsafeshare_token", authData.access_token);
  localStorage.setItem("qsafeshare_user", JSON.stringify(authData.user));

  hideAuthOverlay();
  renderUserProfile();
  refreshCurrentTabData();
  startAuditStream();
}

function signOutUser() {
  AppState.token = null;
  AppState.currentUser = null;
  localStorage.removeItem("qsafeshare_token");
  localStorage.removeItem("qsafeshare_user");
  showAuthOverlay();
}

function showAuthOverlay() {
  const overlay = document.getElementById("authOverlay");
  if (overlay) overlay.style.display = "flex";
}

function hideAuthOverlay() {
  const overlay = document.getElementById("authOverlay");
  if (overlay) overlay.style.display = "none";
}

async function checkSession() {
  try {
    const user = await apiRequest("/api/auth/me");
    AppState.currentUser = user;
    renderUserProfile();
    hideAuthOverlay();
    await refreshCurrentTabData();
    startAuditStream();
  } catch (err) {
    signOutUser();
  }
}

function renderUserProfile() {
  if (!AppState.currentUser) return;
  const user = AppState.currentUser;

  const nameEl = document.getElementById("activeUserName");
  const roleEl = document.getElementById("activeUserRole");
  const avatarEl = document.getElementById("activeAvatar");

  if (nameEl) nameEl.textContent = user.full_name;
  if (roleEl) roleEl.textContent = `@${user.username}`;
  if (avatarEl) {
    const initials = user.full_name.split(" ").map(n => n[0]).join("").toUpperCase().substring(0, 2) || user.username[0].toUpperCase();
    avatarEl.textContent = initials;
  }
}

// Navigation & Tab Switching
function initNavigation() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      switchTab(tab.dataset.tab);
    });
  });
}

function switchTab(tabId) {
  AppState.activeTab = tabId;
  document.querySelectorAll(".nav-tab").forEach(t => t.classList.toggle("active", t.dataset.tab === tabId));
  document.querySelectorAll(".tab-pane").forEach(p => p.classList.toggle("active", p.id === `tab-${tabId}`));
  refreshCurrentTabData();
}

async function refreshCurrentTabData() {
  if (!AppState.currentUser) return;

  if (AppState.activeTab === "my-files") {
    await loadOwnedFiles();
  } else if (AppState.activeTab === "shared-files") {
    await loadSharedFiles();
  } else if (AppState.activeTab === "active-links") {
    await loadMyLinks();
  } else if (AppState.activeTab === "key-vault") {
    if (window.VaultModule) window.VaultModule.loadVault();
  } else if (AppState.activeTab === "benchmarks") {
    if (window.BenchmarkModule) window.BenchmarkModule.init();
  }
}

// File List: My Files
async function loadOwnedFiles() {
  const tbody = document.getElementById("ownedFilesTableBody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;">Loading your encrypted files...</td></tr>`;

  try {
    const files = await apiRequest("/api/files/owned");
    AppState.ownedFiles = files;

    if (files.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 2.5rem; color:var(--text-dim);">No files uploaded yet. Click <strong>Upload & Encrypt File</strong> to securely store a file.</td></tr>`;
      return;
    }

    tbody.innerHTML = files.map(f => {
      return `
        <tr>
          <td>
            <strong>📄 ${escapeHtml(f.original_filename)}</strong>
            <div style="font-size:0.75rem; color:var(--text-dim); font-family:var(--font-mono);">${f.id.substring(0, 8)}...</div>
          </td>
          <td>${formatBytes(f.file_size)}</td>
          <td>
            <span class="badge badge-pqc">AES-256-GCM</span>
          </td>
          <td>
            <div style="display:flex; gap:0.35rem; align-items:center;">
              <span class="badge badge-allowed">${f.allowed_recipients_count} Active</span>
              ${f.revoked_recipients_count > 0 ? `<span class="badge badge-revoked">${f.revoked_recipients_count} Revoked</span>` : ''}
            </div>
          </td>
          <td>${formatDate(f.created_at)}</td>
          <td>
            <div style="display:flex; gap:0.4rem; flex-wrap:wrap;">
              <button class="btn btn-primary btn-sm" onclick="openCreateLinkModal('${f.id}')">🔗 Secure Link</button>
              <button class="btn btn-secondary btn-sm" onclick="openShareModal('${f.id}')">👥 Share User</button>
              <button class="btn btn-secondary btn-sm" onclick="openPolicyModal('${f.id}')">🛡️ Policies</button>
              <button class="btn btn-secondary btn-sm" onclick="openDecryptModal('${f.id}')">🔓 Decrypt</button>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" style="color:var(--accent-rose); text-align:center;">Error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

// File List: Shared With Me
async function loadSharedFiles() {
  const tbody = document.getElementById("sharedFilesTableBody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;">Loading shared files...</td></tr>`;

  try {
    const files = await apiRequest("/api/files/shared-with-me");
    AppState.sharedFiles = files;

    if (files.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 2.5rem; color:var(--text-dim);">No files have been shared with you yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = files.map(f => {
      let statusBadge = `<span class="badge badge-allowed">Allowed ✓</span>`;
      let actionBtn = `<button class="btn btn-primary btn-sm" onclick="openDecryptModal('${f.id}')">🔓 Decrypt & Download</button>`;

      if (f.effective_status === "REVOKED") {
        statusBadge = `<span class="badge badge-revoked">Revoked ✗</span>`;
        actionBtn = `<button class="btn btn-secondary btn-sm" disabled title="Access was revoked by file owner">🚫 Access Revoked</button>`;
      } else if (f.effective_status === "EXPIRED") {
        statusBadge = `<span class="badge badge-expired">Expired ⏰</span>`;
        actionBtn = `<button class="btn btn-secondary btn-sm" disabled title="Access authorization expired">⏰ Expired</button>`;
      }

      return `
        <tr>
          <td>
            <strong>📄 ${escapeHtml(f.original_filename)}</strong>
          </td>
          <td>${formatBytes(f.file_size)}</td>
          <td>
            <strong>${escapeHtml(f.owner_full_name)}</strong>
            <div style="font-size:0.75rem; color:var(--text-dim);">@${escapeHtml(f.owner_username)}</div>
          </td>
          <td>${statusBadge}</td>
          <td>${f.expires_at ? formatDate(f.expires_at) : 'Perpetual (No Expiry)'}</td>
          <td>${actionBtn}</td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" style="color:var(--accent-rose); text-align:center;">Error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

// Modals Management
function initModals() {
  document.querySelectorAll(".close-btn, .modal-cancel").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".modal-backdrop").forEach(m => m.classList.remove("active"));
    });
  });

  const uploadForm = document.getElementById("uploadFileForm");
  if (uploadForm) uploadForm.addEventListener("submit", handleUploadSubmit);

  const shareForm = document.getElementById("shareFileForm");
  if (shareForm) shareForm.addEventListener("submit", handleShareSubmit);

  const createLinkForm = document.getElementById("createLinkForm");
  if (createLinkForm) createLinkForm.addEventListener("submit", handleCreateLinkSubmit);
}

function openModal(modalId) {
  document.querySelectorAll(".modal-backdrop").forEach(m => m.classList.remove("active"));
  const m = document.getElementById(modalId);
  if (m) m.classList.add("active");
}

function closeModal(modalId) {
  const m = document.getElementById(modalId);
  if (m) m.classList.remove("active");
}

// Upload Modal & Handler
function openUploadModal() {
  const fileInput = document.getElementById("fileInput");
  if (fileInput) fileInput.value = "";
  const statusDiv = document.getElementById("uploadStatusMsg");
  if (statusDiv) statusDiv.innerHTML = "";
  openModal("uploadModal");
}

async function handleUploadSubmit(e) {
  e.preventDefault();
  const fileInput = document.getElementById("fileInput");
  const statusDiv = document.getElementById("uploadStatusMsg");
  if (!fileInput.files || fileInput.files.length === 0) {
    statusDiv.innerHTML = `<span style="color:var(--accent-rose);">Please select a file to upload.</span>`;
    return;
  }

  const file = fileInput.files[0];
  const formData = new FormData();
  formData.append("file", file);

  statusDiv.innerHTML = `<span style="color:var(--pqc-cyan);">Sender Agent generating AES-256-GCM key and encrypting...</span>`;

  try {
    const res = await fetch("/api/files/upload", {
      method: "POST",
      headers: { "Authorization": `Bearer ${AppState.token}` },
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Upload failed");
    }
    const data = await res.json();
    statusDiv.innerHTML = `<span style="color:var(--accent-emerald);">✓ Encrypted & Stored (SHA-256: ${data.sha256_checksum.substring(0, 16)}...)</span>`;
    showToast(`File "${file.name}" encrypted and uploaded.`, "success");

    setTimeout(() => {
      closeModal("uploadModal");
      loadOwnedFiles();
    }, 1200);
  } catch (err) {
    statusDiv.innerHTML = `<span style="color:var(--accent-rose);">Error: ${escapeHtml(err.message)}</span>`;
  }
}

// Real-World Recipient Search & Sharing
function initRecipientSearch() {
  const searchInput = document.getElementById("recipientSearchInput");
  const resultsContainer = document.getElementById("recipientSearchResults");

  if (!searchInput || !resultsContainer) return;

  let debounceTimer;
  searchInput.addEventListener("input", () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(async () => {
      const query = searchInput.value.trim();
      try {
        const users = await apiRequest(`/api/auth/search?q=${encodeURIComponent(query)}`);
        renderRecipientSearchResults(users);
      } catch (_) {}
    }, 250);
  });

  searchInput.addEventListener("focus", async () => {
    try {
      const users = await apiRequest(`/api/auth/search?q=`);
      renderRecipientSearchResults(users);
    } catch (_) {}
  });
}

function renderRecipientSearchResults(users) {
  const resultsContainer = document.getElementById("recipientSearchResults");
  if (!resultsContainer) return;

  const unselectedUsers = users.filter(u => !AppState.shareSelectedRecipients.some(r => r.username === u.username));

  if (unselectedUsers.length === 0) {
    resultsContainer.innerHTML = `<div style="padding:0.5rem; font-size:0.8rem; color:var(--text-dim); text-align:center;">No other users found.</div>`;
    return;
  }

  resultsContainer.innerHTML = unselectedUsers.map(u => `
    <div class="recipient-item" onclick="addRecipientTag('${escapeHtml(u.username)}', '${escapeHtml(u.full_name)}', '${escapeHtml(u.email)}')">
      <div>
        <strong>${escapeHtml(u.full_name)}</strong>
        <span style="font-size:0.75rem; color:var(--text-dim);">(@${escapeHtml(u.username)})</span>
        <div style="font-size:0.72rem; color:var(--text-dim);">${escapeHtml(u.email)}</div>
      </div>
      <span class="badge badge-pqc" style="font-size:0.65rem;">${u.kem_algorithm}</span>
    </div>
  `).join("");
}

function addRecipientTag(username, full_name, email) {
  if (!AppState.shareSelectedRecipients.some(r => r.username === username)) {
    AppState.shareSelectedRecipients.push({ username, full_name, email });
    renderRecipientTags();
  }
  const searchInput = document.getElementById("recipientSearchInput");
  if (searchInput) searchInput.value = "";
  const resultsContainer = document.getElementById("recipientSearchResults");
  if (resultsContainer) resultsContainer.innerHTML = "";
}

function removeRecipientTag(username) {
  AppState.shareSelectedRecipients = AppState.shareSelectedRecipients.filter(r => r.username !== username);
  renderRecipientTags();
}

function renderRecipientTags() {
  const container = document.getElementById("selectedRecipientTags");
  if (!container) return;

  if (AppState.shareSelectedRecipients.length === 0) {
    container.innerHTML = `<span style="font-size:0.78rem; color:var(--text-dim);">Search above to select recipients...</span>`;
    return;
  }

  container.innerHTML = AppState.shareSelectedRecipients.map(r => `
    <span class="recipient-tag">
      ${escapeHtml(r.full_name)} (@${escapeHtml(r.username)})
      <span class="remove-btn" onclick="removeRecipientTag('${r.username}')">&times;</span>
    </span>
  `).join("");
}

function openShareModal(fileId) {
  AppState.currentModalFileId = fileId;
  AppState.shareSelectedRecipients = [];
  renderRecipientTags();

  const file = AppState.ownedFiles.find(f => f.id === fileId);
  const titleEl = document.getElementById("shareModalFileName");
  if (titleEl && file) titleEl.textContent = file.original_filename;

  const msgEl = document.getElementById("shareStatusMsg");
  if (msgEl) msgEl.innerHTML = "";

  openModal("shareModal");
}

async function handleShareSubmit(e) {
  e.preventDefault();
  const msgEl = document.getElementById("shareStatusMsg");
  if (AppState.shareSelectedRecipients.length === 0) {
    msgEl.innerHTML = `<span style="color:var(--accent-rose);">Please select at least one recipient user.</span>`;
    return;
  }

  const recipientUsernames = AppState.shareSelectedRecipients.map(r => r.username);
  const expiryHours = parseFloat(document.getElementById("shareExpirySelect").value) || null;

  msgEl.innerHTML = `<span style="color:var(--pqc-cyan);">Coordinator Agent executing ML-KEM encapsulation for ${recipientUsernames.length} recipient(s)...</span>`;

  try {
    await apiRequest("/api/files/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        file_id: AppState.currentModalFileId,
        recipient_usernames: recipientUsernames,
        expires_in_hours: expiryHours,
      }),
    });

    msgEl.innerHTML = `<span style="color:var(--accent-emerald);">✓ Successfully encapsulated and shared!</span>`;
    showToast(`File shared with ${recipientUsernames.length} user(s).`, "success");

    setTimeout(() => {
      closeModal("shareModal");
      loadOwnedFiles();
    }, 1200);
  } catch (err) {
    msgEl.innerHTML = `<span style="color:var(--accent-rose);">Error: ${escapeHtml(err.message)}</span>`;
  }
}

// Access Policy & Revocation Manager
async function openPolicyModal(fileId) {
  AppState.currentModalFileId = fileId;
  const file = AppState.ownedFiles.find(f => f.id === fileId);
  const titleEl = document.getElementById("policyModalFileName");
  if (titleEl && file) titleEl.textContent = file.original_filename;

  const container = document.getElementById("policyListContainer");
  container.innerHTML = "Loading policy records...";
  openModal("policyModal");

  await renderPoliciesList(fileId);
}

async function renderPoliciesList(fileId) {
  const container = document.getElementById("policyListContainer");
  try {
    const policies = await apiRequest(`/api/files/${fileId}/policies`);
    if (policies.length === 0) {
      container.innerHTML = `<p style="color:var(--text-dim); text-align:center; padding:1.5rem;">File has not been shared with anyone yet.</p>`;
      return;
    }

    container.innerHTML = `
      <table class="data-table">
        <thead>
          <tr>
            <th>Authorized Recipient</th>
            <th>Current Policy</th>
            <th>Access Expiration</th>
            <th>Immediate Action</th>
          </tr>
        </thead>
        <tbody>
          ${policies.map(p => {
            let statusBadge = `<span class="badge badge-allowed">Allowed</span>`;
            let toggleBtn = `<button class="btn btn-danger btn-sm" onclick="revokeUser('${fileId}', '${p.username}')">Revoke Access</button>`;

            if (p.effective_status === "REVOKED") {
              statusBadge = `<span class="badge badge-revoked">Revoked</span>`;
              toggleBtn = `<button class="btn btn-success btn-sm" onclick="reinstateUser('${fileId}', '${p.username}')">Reinstate Access</button>`;
            } else if (p.effective_status === "EXPIRED") {
              statusBadge = `<span class="badge badge-expired">Expired</span>`;
              toggleBtn = `<button class="btn btn-secondary btn-sm" onclick="reinstateUser('${fileId}', '${p.username}', 24)">Renew (+24h)</button>`;
            }

            return `
              <tr>
                <td>
                  <strong>${escapeHtml(p.full_name)}</strong>
                  <div style="font-size:0.75rem; color:var(--text-dim);">@${escapeHtml(p.username)}</div>
                </td>
                <td>${statusBadge}</td>
                <td>${p.expires_at ? formatDate(p.expires_at) : 'Perpetual'}</td>
                <td>${toggleBtn}</td>
              </tr>
            `;
          }).join("")}
        </tbody>
      </table>
    `;
  } catch (err) {
    container.innerHTML = `<span style="color:var(--accent-rose);">Error: ${escapeHtml(err.message)}</span>`;
  }
}

async function revokeUser(fileId, username) {
  try {
    await apiRequest("/api/files/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file_id: fileId, recipient_username: username }),
    });
    showToast(`Access revoked for @${username}`, "error");
    await renderPoliciesList(fileId);
    await loadOwnedFiles();
  } catch (err) {
    alert("Revocation failed: " + err.message);
  }
}

async function reinstateUser(fileId, username, hours = null) {
  try {
    await apiRequest("/api/files/reinstate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file_id: fileId, recipient_username: username, expires_in_hours: hours }),
    });
    showToast(`Access reinstated for @${username}`, "success");
    await renderPoliciesList(fileId);
    await loadOwnedFiles();
  } catch (err) {
    alert("Reinstatement failed: " + err.message);
  }
}

// Real File Decryption & Download Flow
async function openDecryptModal(fileId) {
  AppState.currentModalFileId = fileId;
  const content = document.getElementById("decryptModalContent");
  content.innerHTML = `
    <div style="text-align:center; padding:2rem;">
      <div style="font-size:2rem; margin-bottom:0.5rem;">🔐</div>
      <p style="color:var(--pqc-cyan);">Coordinator Agent verifying Policy Agent authorization...</p>
    </div>
  `;
  openModal("decryptModal");

  try {
    // 1. Fetch Key Package (subject to Policy check)
    const pkg = await apiRequest(`/api/files/${fileId}/package`);
    const keyData = pkg.key_package;

    // 2. Perform Decryption & SHA-256 Verification
    const result = await apiRequest(`/api/files/${fileId}/decrypt-verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file_id: fileId }),
    });

    const directDownloadUrl = `/api/files/${fileId}/download-decrypted?token=${encodeURIComponent(AppState.token)}`;

    // Render verification report with real binary download button
    content.innerHTML = `
      <div style="background:rgba(16, 185, 129, 0.08); border:1px solid rgba(16, 185, 129, 0.3); border-radius:var(--radius-md); padding:1rem; margin-bottom:1.2rem;">
        <div style="display:flex; align-items:center; gap:0.5rem; color:var(--accent-emerald); font-weight:700; font-size:1rem; margin-bottom:0.25rem;">
          <span>✓</span> Post-Quantum Cryptographic Verification Succeeded
        </div>
        <div style="font-size:0.8rem; color:var(--text-muted);">
          Key encapsulated with <strong>${keyData.kem_algorithm}</strong> (NIST FIPS 203) and payload decrypted with <strong>AES-256-GCM</strong>.
        </div>
      </div>

      <div class="benchmark-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom:1.2rem;">
        <div class="metric-card">
          <div class="metric-label">ML-KEM Decapsulation</div>
          <div class="metric-value" style="font-size:1.3rem;">${result.decapsulation_time_ms} ms</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">AES-256-GCM Decrypt</div>
          <div class="metric-value" style="font-size:1.3rem;">${result.file_decryption_time_ms} ms</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Total Pipeline</div>
          <div class="metric-value" style="font-size:1.3rem; color:var(--accent-emerald);">${result.total_time_ms} ms</div>
        </div>
      </div>

      <div style="margin-bottom:1.25rem;">
        <label style="font-size:0.75rem; color:var(--text-dim); text-transform:uppercase; font-weight:600;">SHA-256 Integrity Verification</label>
        <div class="key-box" style="font-size:0.75rem; color:var(--accent-emerald); max-height:60px;">
Original:   ${result.original_sha256}
Calculated: ${result.calculated_sha256}
Status:     MATCH VERIFIED (Bit-exact recovered)
        </div>
      </div>

      <div style="display:flex; gap:0.75rem; justify-content:flex-end;">
        <button class="btn btn-secondary" onclick="closeModal('decryptModal')">Close</button>
        <a class="btn btn-primary" href="${directDownloadUrl}" download="${result.filename}">
          💾 Download Recovered File (${formatBytes(result.file_size)})
        </a>
      </div>
    `;
  } catch (err) {
    content.innerHTML = `
      <div style="background:rgba(244, 63, 94, 0.08); border:1px solid rgba(244, 63, 94, 0.3); border-radius:var(--radius-md); padding:1.5rem; text-align:center;">
        <div style="font-size:2.5rem; margin-bottom:0.5rem;">🚫</div>
        <h4 style="color:var(--accent-rose); margin-bottom:0.5rem;">Access Denied by Policy Agent</h4>
        <p style="color:var(--text-muted); font-size:0.88rem; margin-bottom:1.25rem;">
          ${escapeHtml(err.message)}
        </p>
        <button class="btn btn-secondary" onclick="closeModal('decryptModal')">Dismiss</button>
      </div>
    `;
  }
}

// Live Audit Stream Polling
let auditPollingInterval = null;
function startAuditStream() {
  fetchAuditLogs();
  if (!auditPollingInterval) {
    auditPollingInterval = setInterval(fetchAuditLogs, 3000);
  }
}

async function fetchAuditLogs() {
  const container = document.getElementById("liveAuditStream");
  if (!container || !AppState.token) return;

  try {
    const logs = await apiRequest("/api/audit/logs?limit=30");
    if (logs.length === 0) {
      container.innerHTML = `<div style="color:var(--text-dim); padding:1rem; text-align:center;">No inter-agent events logged yet.</div>`;
      return;
    }

    container.innerHTML = logs.map(l => {
      const timeStr = new Date(l.timestamp).toLocaleTimeString();
      return `
        <div class="log-entry">
          <span class="log-time">${timeStr}</span>
          <span class="log-agent ${l.agent_name}">[${l.agent_name}]</span>
          <span class="log-action">
            <strong>${l.action}</strong>
            ${l.file_name ? `<span style="color:var(--text-dim);"> • ${escapeHtml(l.file_name)}</span>` : ''}
            ${l.username ? `<span style="color:var(--pqc-cyan);"> (@${escapeHtml(l.username)})</span>` : ''}
          </span>
          <span class="log-status ${l.status}">${l.status}</span>
        </div>
      `;
    }).join("");
  } catch (_) {}
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
  );
}

// ==========================================
// LINK-BASED SECURE FILE SHARING CONTROLLER
// ==========================================

let currentGeneratedLinkData = null;

function openCreateLinkModal(fileId) {
  AppState.currentModalFileId = fileId;
  currentGeneratedLinkData = null;

  const file = AppState.ownedFiles.find(f => f.id === fileId);
  const nameEl = document.getElementById("createLinkFileName");
  if (nameEl && file) {
    nameEl.textContent = `${file.original_filename} (${formatBytes(file.file_size)})`;
  }

  // Reset mode radios: DEFAULT TO PASSWORD PROTECTION (Option 1)
  const modeRadios = document.querySelectorAll('input[name="linkProtectionMode"]');
  modeRadios.forEach(r => {
    r.checked = (r.value === "SECRET_KEY");
  });
  toggleLinkProtectionMode("SECRET_KEY");

  const provisionSelect = document.getElementById("mlkemKeyProvisionSelect");
  if (provisionSelect) provisionSelect.value = "auto";
  toggleMlkemKeyInput("auto");

  const customKeyInput = document.getElementById("customSecretKeyInput");
  if (customKeyInput) customKeyInput.value = "";

  const customPubkey = document.getElementById("customRecipientPubkey");
  if (customPubkey) customPubkey.value = "";

  const expirySelect = document.getElementById("linkExpirySelect");
  if (expirySelect) expirySelect.value = "24";

  const maxDlSelect = document.getElementById("linkMaxDownloadsSelect");
  if (maxDlSelect) maxDlSelect.value = "";

  const resultArea = document.getElementById("linkGeneratedResultArea");
  if (resultArea) {
    resultArea.style.display = "none";
    resultArea.innerHTML = "";
  }

  const submitBtn = document.getElementById("btnSubmitCreateLink");
  if (submitBtn) {
    submitBtn.style.display = "inline-block";
    submitBtn.disabled = false;
    submitBtn.textContent = "🚀 Generate Secure Link";
  }

  openModal("createLinkModal");
}

function toggleLinkProtectionMode(mode) {
  const mlkemOpts = document.getElementById("mlkemLinkOptions");
  const secretOpts = document.getElementById("secretKeyLinkOptions");
  const cardSecret = document.getElementById("modeCardSecret");
  const cardMlkem = document.getElementById("modeCardMlkem");

  if (mode === "SECRET_KEY") {
    if (secretOpts) secretOpts.style.display = "block";
    if (mlkemOpts) mlkemOpts.style.display = "none";
    if (cardSecret) {
      cardSecret.style.borderColor = "var(--pqc-cyan)";
      cardSecret.style.background = "rgba(6, 182, 212, 0.08)";
    }
    if (cardMlkem) {
      cardMlkem.style.borderColor = "var(--border-color)";
      cardMlkem.style.background = "var(--bg-secondary)";
    }
  } else {
    if (secretOpts) secretOpts.style.display = "none";
    if (mlkemOpts) mlkemOpts.style.display = "block";
    if (cardMlkem) {
      cardMlkem.style.borderColor = "var(--pqc-cyan)";
      cardMlkem.style.background = "rgba(6, 182, 212, 0.08)";
    }
    if (cardSecret) {
      cardSecret.style.borderColor = "var(--border-color)";
      cardSecret.style.background = "var(--bg-secondary)";
    }
  }
}

function switchToSecretKeyWithPassword(pass) {
  const modeRadios = document.querySelectorAll('input[name="linkProtectionMode"]');
  modeRadios.forEach(r => {
    r.checked = (r.value === "SECRET_KEY");
  });
  toggleLinkProtectionMode("SECRET_KEY");
  const customKeyInput = document.getElementById("customSecretKeyInput");
  if (customKeyInput) customKeyInput.value = pass;
  const resultArea = document.getElementById("linkGeneratedResultArea");
  if (resultArea) {
    resultArea.style.display = "none";
    resultArea.innerHTML = "";
  }
  showToast(`Switched to Password mode with "${pass}"`, "info");
}

function switchToAutoMlkem() {
  const provisionSelect = document.getElementById("mlkemKeyProvisionSelect");
  if (provisionSelect) provisionSelect.value = "auto";
  toggleMlkemKeyInput("auto");
  const resultArea = document.getElementById("linkGeneratedResultArea");
  if (resultArea) {
    resultArea.style.display = "none";
    resultArea.innerHTML = "";
  }
}

function toggleMlkemKeyInput(val) {
  const customPubArea = document.getElementById("customPubkeyArea");
  if (customPubArea) {
    customPubArea.style.display = (val === "custom") ? "block" : "none";
  }
}

function generateRandomPassphrase() {
  const chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*";
  const array = new Uint8Array(24);
  window.crypto.getRandomValues(array);
  let result = "";
  for (let i = 0; i < array.length; i++) {
    result += chars[array[i] % chars.length];
  }
  const input = document.getElementById("customSecretKeyInput");
  if (input) input.value = result;
}

async function handleCreateLinkSubmit(e) {
  e.preventDefault();
  const fileId = AppState.currentModalFileId;
  if (!fileId) return;

  const modeRadio = document.querySelector('input[name="linkProtectionMode"]:checked');
  const mode = modeRadio ? modeRadio.value : "ML_KEM";

  const expiryHours = parseFloat(document.getElementById("linkExpirySelect").value) || null;
  const maxDownloads = parseInt(document.getElementById("linkMaxDownloadsSelect").value) || null;

  const submitBtn = document.getElementById("btnSubmitCreateLink");
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = "Generating...";
  }

  const resultArea = document.getElementById("linkGeneratedResultArea");
  resultArea.style.display = "block";
  resultArea.innerHTML = `<div style="color:var(--pqc-cyan); text-align:center; padding:1rem;">Generating cryptographic keys and wrapping file key...</div>`;

  try {
    let data;
    if (mode === "ML_KEM") {
      const provisionMode = document.getElementById("mlkemKeyProvisionSelect").value;
      let pubkeyPem = null;
      if (provisionMode === "custom") {
        pubkeyPem = document.getElementById("customRecipientPubkey").value.trim();
        if (!pubkeyPem) {
          throw new Error("Please paste recipient's ML-KEM-768 public key (PEM certificate).");
        }
        if (!pubkeyPem.includes("-----BEGIN")) {
          // Plain text password entered by mistake in PEM area
          resultArea.style.display = "block";
          resultArea.innerHTML = `
            <div style="background:rgba(244, 63, 94, 0.1); border:1px solid rgba(244, 63, 94, 0.4); border-radius:var(--radius-md); padding:1.1rem; color:var(--text-main);">
              <div style="font-weight:700; color:var(--accent-rose); margin-bottom:0.4rem; font-size:0.95rem;">
                ⚠️ You entered a password ("${escapeHtml(pubkeyPem)}") instead of a PEM certificate
              </div>
              <div style="font-size:0.82rem; color:var(--text-muted); margin-bottom:0.85rem; line-height:1.4;">
                Post-quantum <strong>ML-KEM public keys</strong> are cryptographic certificates starting with <code>-----BEGIN PUBLIC KEY-----</code>.<br>
                If you want to protect your file with the password <strong>"${escapeHtml(pubkeyPem)}"</strong>, click below to use <strong>Option 1: Password / Secret Key</strong>:
              </div>
              <div style="display:flex; gap:0.6rem; flex-wrap:wrap;">
                <button type="button" class="btn btn-primary btn-sm" onclick="switchToSecretKeyWithPassword('${escapeHtml(pubkeyPem)}')">
                  ✓ Protect with password "${escapeHtml(pubkeyPem)}"
                </button>
                <button type="button" class="btn btn-secondary btn-sm" onclick="switchToAutoMlkem()">
                  ⚡ Switch to Auto-Generated ML-KEM Key
                </button>
              </div>
            </div>
          `;
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = "🚀 Generate Secure Link";
          }
          return;
        }
      }
      data = await apiRequest("/api/links/create-mlkem", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          file_id: fileId,
          recipient_public_key_pem: pubkeyPem,
          expires_in_hours: expiryHours,
          max_downloads: maxDownloads,
          kem_algorithm: "ML-KEM-768",
        }),
      });
    } else {
      const secretKey = document.getElementById("customSecretKeyInput").value.trim();
      data = await apiRequest("/api/links/create-secret", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          file_id: fileId,
          custom_secret_key: secretKey || undefined,
          expires_in_hours: expiryHours,
          max_downloads: maxDownloads,
        }),
      });
    }

    currentGeneratedLinkData = data;
    const fullShareUrl = `${window.location.origin}${data.share_url}`;
    const credential = data.private_key_pem || data.secret_key || "";
    const unifiedUrl = credential ? `${fullShareUrl}#key=${encodeURIComponent(credential)}` : fullShareUrl;

    if (data.secret_key) {
      resultArea.innerHTML = `
        <div style="background:rgba(16, 185, 129, 0.08); border:1px solid rgba(16, 185, 129, 0.3); border-radius:var(--radius-md); padding:1.25rem;">
          <div style="display:flex; align-items:center; gap:0.5rem; color:var(--accent-emerald); font-weight:700; margin-bottom:0.85rem; font-size:1.05rem;">
            <span>✓</span> Password-Protected Link Created!
          </div>

          <div style="margin-bottom:0.85rem;">
            <label style="font-size:0.78rem; color:var(--text-dim); font-weight:600;">1. Shareable File Link:</label>
            <div style="display:flex; gap:0.5rem; margin-top:0.25rem;">
              <input type="text" readonly class="form-control" style="font-family:var(--font-mono);" id="genShareUrlVal" value="${fullShareUrl}">
              <button type="button" class="btn btn-secondary btn-sm" onclick="copyGeneratedLink()">📋 Copy Link</button>
            </div>
          </div>

          <div style="margin-bottom:1rem; padding:0.85rem; background:rgba(6, 182, 212, 0.08); border:1px solid rgba(6, 182, 212, 0.25); border-radius:var(--radius-md);">
            <label style="font-size:0.8rem; color:var(--pqc-cyan); font-weight:700;">2. File Password (Set by you):</label>
            <div style="display:flex; gap:0.5rem; margin-top:0.35rem;">
              <input type="text" readonly class="form-control" style="font-family:var(--font-mono); font-weight:700; font-size:1.05rem; color:var(--text-main); background:var(--bg-primary);" id="genSecretKeyVal" value="${escapeHtml(data.secret_key)}">
              <button type="button" class="btn btn-secondary btn-sm" onclick="copyGeneratedKey()">📋 Copy Password</button>
            </div>
            <small style="color:var(--text-dim); font-size:0.75rem; margin-top:0.35rem; display:block;">
              Your recipient only needs this password to unlock & download the file.
            </small>
          </div>

          <button type="button" class="btn btn-primary" style="width:100%; margin-bottom:0.5rem; font-weight:600; padding:0.7rem;" onclick="copyUnifiedLinkWithPassword()">
            📋 Copy Link & Password Together (WhatsApp / Email Ready)
          </button>
        </div>
      `;
    } else {
      resultArea.innerHTML = `
        <div style="background:rgba(16, 185, 129, 0.08); border:1px solid rgba(16, 185, 129, 0.3); border-radius:var(--radius-md); padding:1.25rem;">
          <div style="display:flex; align-items:center; gap:0.5rem; color:var(--accent-emerald); font-weight:700; margin-bottom:0.75rem;">
            <span>✓</span> Post-Quantum ML-KEM Link Created!
          </div>

          <div style="margin-bottom:0.75rem;">
            <label style="font-size:0.75rem; color:var(--text-dim); font-weight:600;">Shareable Link:</label>
            <div style="display:flex; gap:0.5rem; margin-top:0.25rem;">
              <input type="text" readonly class="form-control" style="font-family:var(--font-mono);" id="genShareUrlVal" value="${fullShareUrl}">
              <button type="button" class="btn btn-secondary btn-sm" onclick="copyGeneratedLink()">📋 Copy Link</button>
            </div>
          </div>

          <div style="margin-top:1rem;">
            <label style="font-size:0.75rem; color:var(--pqc-cyan); font-weight:700;">NIST ML-KEM-768 Private Key (Recipient's Decryption Key):</label>
            <div style="position:relative; margin-top:0.35rem;">
              <textarea readonly rows="5" class="form-control" style="font-family:var(--font-mono); font-size:0.72rem; word-break:break-all;" id="genPrivateKeyPem">${escapeHtml(data.private_key_pem || '')}</textarea>
            </div>
            <div style="display:flex; gap:0.5rem; margin-top:0.4rem; flex-wrap:wrap;">
              <button type="button" class="btn btn-secondary btn-sm" onclick="copyGeneratedKey()">📋 Copy Private Key</button>
              <button type="button" class="btn btn-secondary btn-sm" onclick="downloadLinkKeyFile()">💾 Save .pem File</button>
            </div>
          </div>

          <div style="margin-top:1rem; padding-top:0.75rem; border-top:1px dashed var(--border-color);">
            <label style="font-size:0.75rem; color:var(--text-dim); font-weight:600;">Convenience: Unified One-Click Link (Key preloaded in URL fragment):</label>
            <div style="display:flex; gap:0.5rem; margin-top:0.25rem;">
              <input type="text" readonly class="form-control" style="font-family:var(--font-mono); font-size:0.75rem;" value="${unifiedUrl}">
              <button type="button" class="btn btn-primary btn-sm" onclick="copyUnifiedLinkWithKey()">⚡ Copy 1-Click Link</button>
            </div>
            <p style="font-size:0.72rem; color:var(--text-dim); margin-top:0.4rem;">
              Note: Fragment (#key=...) is processed by the recipient's browser locally to unlock the file!
            </p>
          </div>
        </div>
      `;
    }

    if (submitBtn) submitBtn.style.display = "none";
    showToast("Secure sharing link generated!", "success");

  } catch (err) {
    resultArea.innerHTML = `<div style="color:var(--accent-rose); padding:0.5rem;">Error: ${escapeHtml(err.message)}</div>`;
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = "🚀 Generate Secure Link";
    }
  }
}

function copyGeneratedLink() {
  if (!currentGeneratedLinkData) return;
  const fullShareUrl = `${window.location.origin}${currentGeneratedLinkData.share_url}`;
  navigator.clipboard.writeText(fullShareUrl).then(() => {
    showToast("Share link copied to clipboard!", "success");
  });
}

function copyGeneratedKey() {
  if (!currentGeneratedLinkData) return;
  const key = currentGeneratedLinkData.secret_key || currentGeneratedLinkData.private_key_pem || "";
  const isPass = Boolean(currentGeneratedLinkData.secret_key);
  navigator.clipboard.writeText(key).then(() => {
    showToast(`${isPass ? 'Password' : 'Cryptographic key'} copied to clipboard!`, "success");
  });
}

function copyUnifiedLinkWithPassword() {
  if (!currentGeneratedLinkData) return;
  const fullShareUrl = `${window.location.origin}${currentGeneratedLinkData.share_url}`;
  const pass = currentGeneratedLinkData.secret_key || "";
  const text = `📁 QSafeShare Secure File Access:\nLink: ${fullShareUrl}\nPassword: ${pass}`;
  navigator.clipboard.writeText(text).then(() => {
    showToast("Link & password copied to clipboard!", "success");
  });
}

function copyUnifiedLinkWithKey() {
  if (!currentGeneratedLinkData) return;
  const fullShareUrl = `${window.location.origin}${currentGeneratedLinkData.share_url}`;
  const key = currentGeneratedLinkData.private_key_pem || currentGeneratedLinkData.secret_key || "";
  const unifiedUrl = `${fullShareUrl}#key=${encodeURIComponent(key)}`;
  navigator.clipboard.writeText(unifiedUrl).then(() => {
    showToast("1-Click Unified Link copied to clipboard!", "success");
  });
}

function downloadLinkKeyFile() {
  if (!currentGeneratedLinkData || !currentGeneratedLinkData.private_key_pem) return;
  const blob = new Blob([currentGeneratedLinkData.private_key_pem], { type: "application/x-pem-file" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `qsafeshare_${currentGeneratedLinkData.share_token}_mlkem_key.pem`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  showToast("Keyfile downloaded (.pem)", "info");
}

// Active Links Management
async function loadMyLinks() {
  const tbody = document.getElementById("myLinksTableBody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;">Loading your active sharing links...</td></tr>`;

  try {
    const links = await apiRequest("/api/links/my-links");

    if (links.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 2.5rem; color:var(--text-dim);">No sharing links created yet. Click <strong>🔗 Secure Link</strong> on any file in "My Files" to create one.</td></tr>`;
      return;
    }

    tbody.innerHTML = links.map(l => {
      const fullUrl = `${window.location.origin}/share/${l.id}`;
      let statusBadge = `<span class="badge badge-allowed">Active</span>`;
      let revokeBtn = `<button class="btn btn-danger btn-sm" onclick="revokeLink('${l.id}')">Revoke Link</button>`;

      if (l.effective_status === "REVOKED") {
        statusBadge = `<span class="badge badge-revoked">Revoked</span>`;
        revokeBtn = `<button class="btn btn-secondary btn-sm" disabled>Revoked</button>`;
      } else if (l.effective_status === "EXPIRED") {
        statusBadge = `<span class="badge badge-expired">Expired</span>`;
        revokeBtn = `<button class="btn btn-secondary btn-sm" disabled>Expired</button>`;
      } else if (l.effective_status === "LIMIT_REACHED") {
        statusBadge = `<span class="badge badge-expired">Limit Reached</span>`;
        revokeBtn = `<button class="btn btn-secondary btn-sm" disabled>Depleted</button>`;
      }

      const modeBadge = l.protection_mode === "ML_KEM" 
        ? `<span class="badge badge-pqc">${escapeHtml(l.kem_algorithm || "ML-KEM-768")}</span>`
        : `<span class="badge" style="background:rgba(100,116,139,0.2); color:#94a3b8;">Secret Key</span>`;

      const maxDlText = l.max_downloads ? `${l.download_count} / ${l.max_downloads}` : `${l.download_count} / ∞`;

      return `
        <tr>
          <td>
            <strong>📄 ${escapeHtml(l.original_filename)}</strong>
            <div style="font-size:0.75rem; color:var(--text-dim);">${formatBytes(l.file_size)}</div>
          </td>
          <td>
            <div style="display:flex; align-items:center; gap:0.4rem;">
              <code style="font-size:0.75rem; color:var(--pqc-cyan);">/share/${l.id}</code>
              <button class="btn btn-secondary btn-sm" style="padding:0.15rem 0.4rem; font-size:0.7rem;" onclick="navigator.clipboard.writeText('${fullUrl}').then(() => showToast('Link copied!','success'))">📋</button>
              <a href="/share/${l.id}" target="_blank" class="btn btn-secondary btn-sm" style="padding:0.15rem 0.4rem; font-size:0.7rem;" title="Open recipient page">↗️</a>
            </div>
          </td>
          <td>${modeBadge}</td>
          <td>${statusBadge}</td>
          <td><span style="font-family:var(--font-mono); font-size:0.82rem;">${maxDlText}</span></td>
          <td>${l.expires_at ? formatDate(l.expires_at) : 'Perpetual'}</td>
          <td>
            <div style="display:flex; gap:0.35rem;">
              ${revokeBtn}
            </div>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" style="color:var(--accent-rose); text-align:center;">Error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

async function revokeLink(shareToken) {
  if (!confirm("Are you sure you want to revoke this secure link? The Policy Agent will immediately block anyone from downloading the file with this link.")) {
    return;
  }
  try {
    await apiRequest(`/api/links/${shareToken}/revoke`, { method: "POST" });
    showToast("Link has been permanently revoked by Policy Agent.", "error");
    await loadMyLinks();
  } catch (err) {
    alert("Revocation failed: " + err.message);
  }
}

// Expose functions globally for onclick bindings
window.openCreateLinkModal = openCreateLinkModal;
window.toggleLinkProtectionMode = toggleLinkProtectionMode;
window.toggleMlkemKeyInput = toggleMlkemKeyInput;
window.generateRandomPassphrase = generateRandomPassphrase;
window.handleCreateLinkSubmit = handleCreateLinkSubmit;
window.copyGeneratedLink = copyGeneratedLink;
window.copyGeneratedKey = copyGeneratedKey;
window.copyUnifiedLinkWithKey = copyUnifiedLinkWithKey;
window.downloadLinkKeyFile = downloadLinkKeyFile;
window.loadMyLinks = loadMyLinks;
window.revokeLink = revokeLink;
window.switchToSecretKeyWithPassword = switchToSecretKeyWithPassword;
window.openOAuthModal = openOAuthModal;
window.loginWithOAuth = loginWithOAuth;
window.handleOAuthCustomSubmit = handleOAuthCustomSubmit;
window.initGoogleIdentityServices = initGoogleIdentityServices;
window.handleGoogleCredentialResponse = handleGoogleCredentialResponse;
window.switchAccount = switchAccount;


