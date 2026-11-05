/**
 * User Management & RBAC View
 * Inspects current profile (/me), tests user lookup (/users/{id}),
 * partial PATCH updates with field inclusion toggles, Casbin 403 authorization,
 * soft deactivation, and paginated user directory.
 */
import { getMe, getUser, listUsers, updateUser } from './user.api.js';
import { sessionStore } from '../../core/session-store.js';
import { showToast, formatDate, escapeHtml, renderBadge, copyToClipboard } from '../../shared/ui-helpers.js';

export class UserView {
    constructor() {
        this.currentUser = null;
        this.directoryPage = 1;
        this.directoryPageSize = 5;
    }

    render() {
        const activeSlot = sessionStore.getActiveSlot();
        const session = sessionStore.getSession(activeSlot);

        if (!session?.accessToken) {
            return `
                <div class="module-card">
                    <div class="card-header">
                        <h2>User Management & RBAC</h2>
                    </div>
                    <div class="empty-state">
                        <div style="font-size: 2.5rem; margin-bottom: var(--space-2);">🔒</div>
                        <h3>Authentication Required</h3>
                        <p>No active token found for <strong>${activeSlot === 'device_b' ? 'Device B' : 'Device A'}</strong>.</p>
                        <p class="text-muted">Please log in or click <strong>"1-Click Demo Setup"</strong> in the Authentication tab first.</p>
                    </div>
                </div>
            `;
        }

        return `
            <div class="module-card">
                <div class="card-header">
                    <div class="header-title">
                        <h2>User Identity & Access Management (RBAC)</h2>
                        <span class="subtitle">Inspecting current subject (${activeSlot}), testing attribute mutations, and Casbin access policy checks</span>
                    </div>
                    <div class="header-actions">
                        <button class="btn btn-secondary" id="btn-user-refresh">↻ Refresh Profile</button>
                    </div>
                </div>

                <!-- 2-Column Grid: Profile Card & Mutation / Lookup Box -->
                <div class="grid-2">
                    <!-- Current User Card -->
                    <div class="card">
                        <div class="card-header">
                            <div class="d-flex align-items-center gap-2">
                                <span style="font-size: 1.5rem;">👤</span>
                                <div>
                                    <h3 id="user-display-name" class="m-0">Loading Profile...</h3>
                                    <span class="text-muted text-xs" id="user-display-email">-</span>
                                </div>
                            </div>
                            <span id="user-detail-role-badge"></span>
                        </div>

                        <div class="profile-details-table">
                            <div class="detail-row">
                                <span class="label">User ID:</span>
                                <span class="val breakable-mono" id="user-detail-id">-</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">Assigned Role:</span>
                                <span class="val" id="user-detail-role">-</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">Account Status:</span>
                                <span class="val" id="user-detail-status">-</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">Email Verified:</span>
                                <span class="val" id="user-detail-verified">-</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">Security Version:</span>
                                <span class="val bold" id="user-detail-sec-ver">-</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">Created At:</span>
                                <span class="val text-xs font-mono" id="user-detail-created">-</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">Last Updated:</span>
                                <span class="val text-xs font-mono" id="user-detail-updated">-</span>
                            </div>
                        </div>

                        <!-- Direct Lookup by ID Input -->
                        <div class="mt-3 p-3 bg-surface-secondary border-radius-sm" style="background-color: var(--bg-surface-secondary); border-radius: var(--radius-sm); border: 1px solid var(--border-default);">
                            <h4 class="mb-2">Lookup User by ID</h4>
                            <div class="d-flex gap-2">
                                <input type="number" id="input-lookup-id" class="form-input" placeholder="User ID" min="1" style="max-width: 120px;">
                                <button class="btn btn-sm btn-secondary" id="btn-lookup-user">Fetch User</button>
                            </div>
                            <div id="lookup-result-box" class="mt-2 text-xs" style="display: none;"></div>
                        </div>
                    </div>

                    <!-- Actions & Mutation Box (PATCH) -->
                    <div class="card">
                        <h4>Partial Update (PATCH /api/v1/users/{id})</h4>
                        <p class="text-xs text-muted mb-3">Test selective field updates. Only checked fields will be sent in the JSON payload.</p>
                        
                        <form id="form-user-update">
                            <div class="form-group">
                                <label class="d-flex align-items-center gap-2">
                                    <input type="checkbox" id="chk-update-name" checked>
                                    <span>Update Full Name:</span>
                                </label>
                                <input type="text" id="edit-user-fullname" class="form-input" placeholder="Enter updated name">
                            </div>

                            <div class="form-group">
                                <label class="d-flex align-items-center gap-2">
                                    <input type="checkbox" id="chk-update-role">
                                    <span>Update Role (Admin Only):</span>
                                </label>
                                <select id="edit-user-role" class="form-select">
                                    <option value="user">user</option>
                                    <option value="admin">admin</option>
                                </select>
                            </div>

                            <div class="form-group">
                                <label class="d-flex align-items-center gap-2">
                                    <input type="checkbox" id="chk-update-active">
                                    <span>Update Active Status:</span>
                                </label>
                                <select id="edit-user-active" class="form-select">
                                    <option value="true">Active (true)</option>
                                    <option value="false">Inactive (false)</option>
                                </select>
                            </div>

                            <button type="submit" class="btn btn-primary w-100" id="btn-save-profile">
                                Save Changes (PATCH)
                            </button>
                        </form>

                        <div class="card-section mt-4 pt-3" style="border-top: 1px solid var(--border-default);">
                            <h4>Security & Governance Controls</h4>
                            <div class="d-flex flex-column gap-2 mt-2">
                                <button class="btn btn-outline btn-warning w-100" id="btn-test-rbac-forbidden" title="Simulates accessing Admin directory">
                                    🛡️ Test Casbin RBAC Guard (Attempt Admin Action)
                                </button>
                                <button class="btn btn-danger w-100" id="btn-deactivate-user" title="Sets is_active=false on this account">
                                    ⚠️ Soft-Deactivate My Account
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Paginated Directory Table -->
                <div class="card mt-4">
                    <div class="section-header-row">
                        <div>
                            <h3>Tenant User Directory</h3>
                            <p class="section-desc">Paginated directory across tenant (Requires admin role or users:read permission)</p>
                        </div>
                        <div class="d-flex align-items-center gap-2">
                            <button class="btn btn-sm btn-outline" id="btn-dir-prev" disabled>&larr; Prev</button>
                            <span class="font-mono text-xs bold" id="dir-page-indicator">Page 1</span>
                            <button class="btn btn-sm btn-outline" id="btn-dir-next">Next &rarr;</button>
                        </div>
                    </div>

                    <div class="table-responsive">
                        <table class="data-table" id="table-user-directory">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Email</th>
                                    <th>Full Name</th>
                                    <th>Role</th>
                                    <th>Status</th>
                                    <th>Verified</th>
                                    <th>Created</th>
                                </tr>
                            </thead>
                            <tbody id="tbody-user-directory">
                                <tr><td colspan="7" class="text-center text-muted">Loading directory...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    }

    bindEvents() {
        const refreshBtn = document.getElementById('btn-user-refresh');
        if (refreshBtn) refreshBtn.addEventListener('click', () => this.loadProfile(true));

        const updateForm = document.getElementById('form-user-update');
        if (updateForm) {
            updateForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleUpdateProfile();
            });
        }

        const lookupBtn = document.getElementById('btn-lookup-user');
        if (lookupBtn) {
            lookupBtn.addEventListener('click', () => this.handleLookupUser());
        }

        const rbacBtn = document.getElementById('btn-test-rbac-forbidden');
        if (rbacBtn) {
            rbacBtn.addEventListener('click', () => this.handleTestRbac());
        }

        const deactBtn = document.getElementById('btn-deactivate-user');
        if (deactBtn) {
            deactBtn.addEventListener('click', () => this.handleDeactivate());
        }

        const prevBtn = document.getElementById('btn-dir-prev');
        const nextBtn = document.getElementById('btn-dir-next');
        if (prevBtn) {
            prevBtn.addEventListener('click', () => {
                if (this.directoryPage > 1) {
                    this.directoryPage--;
                    this.loadDirectory();
                }
            });
        }
        if (nextBtn) {
            nextBtn.addEventListener('click', () => {
                this.directoryPage++;
                this.loadDirectory();
            });
        }

        this.loadProfile(false);
        this.loadDirectory();
    }

    cleanup() {}

    async loadProfile(manual = false) {
        try {
            const res = await getMe();
            if (res.ok && res.data) {
                const user = res.data;
                this.currentUser = user;

                const nameEl = document.getElementById('user-display-name');
                const emailEl = document.getElementById('user-display-email');
                const idEl = document.getElementById('user-detail-id');
                const roleEl = document.getElementById('user-detail-role');
                const statusEl = document.getElementById('user-detail-status');
                const verEl = document.getElementById('user-detail-verified');
                const secEl = document.getElementById('user-detail-sec-ver');
                const createdEl = document.getElementById('user-detail-created');
                const updatedEl = document.getElementById('user-detail-updated');
                const editInput = document.getElementById('edit-user-fullname');
                const roleBadge = document.getElementById('user-detail-role-badge');

                if (nameEl) nameEl.textContent = user.name || 'Unnamed User';
                if (emailEl) emailEl.textContent = user.email;
                if (idEl) idEl.textContent = user.id;
                if (roleEl) roleEl.innerHTML = renderBadge(user.role === 'admin' ? 'danger' : 'info', user.role || 'user');
                if (statusEl) statusEl.innerHTML = renderBadge(user.is_active ? 'success' : 'danger', user.is_active ? 'Active' : 'Inactive');
                if (verEl) verEl.innerHTML = renderBadge(user.is_verified ? 'success' : 'warning', user.is_verified ? 'Verified' : 'Unverified');
                if (secEl) secEl.textContent = user.security_version ?? 1;
                if (createdEl) createdEl.textContent = formatDate(user.created_at);
                if (updatedEl) updatedEl.textContent = formatDate(user.updated_at);
                if (editInput) editInput.value = user.name || '';
                if (roleBadge) roleBadge.innerHTML = renderBadge(user.role === 'admin' ? 'danger' : 'info', user.role || 'user');

                if (manual) showToast('Profile refreshed', 'success', 1500);
            } else {
                showToast(`Failed to load profile: ${res.data?.message || res.status}`, 'danger', 3000);
            }
        } catch (err) {
            showToast(`Profile load error: ${err.message}`, 'danger', 3000);
        }
    }

    async handleLookupUser() {
        const idInput = document.getElementById('input-lookup-id');
        const resultBox = document.getElementById('lookup-result-box');
        const userId = idInput?.value;

        if (!userId) {
            showToast('Enter a valid User ID', 'warning');
            return;
        }

        const res = await getUser(userId);
        if (resultBox) {
            resultBox.style.display = 'block';
            if (res.ok && res.data) {
                resultBox.innerHTML = `
                    <div class="card p-2 bg-surface">
                        <strong>User #${res.data.id}:</strong> ${escapeHtml(res.data.name)} &lt;${escapeHtml(res.data.email)}&gt; | Role: <code>${escapeHtml(res.data.role)}</code>
                    </div>
                `;
            } else {
                resultBox.innerHTML = `<span class="badge badge-danger">Lookup failed (Status ${res.status}): ${escapeHtml(res.data?.error?.message || 'Not Found')}</span>`;
            }
        }
    }

    async handleUpdateProfile() {
        if (!this.currentUser) return;
        const chkName = document.getElementById('chk-update-name')?.checked;
        const chkRole = document.getElementById('chk-update-role')?.checked;
        const chkActive = document.getElementById('chk-update-active')?.checked;

        const payload = {};
        if (chkName) {
            payload.name = document.getElementById('edit-user-fullname')?.value.trim();
        }
        if (chkRole) {
            payload.role = document.getElementById('edit-user-role')?.value;
        }
        if (chkActive) {
            payload.is_active = document.getElementById('edit-user-active')?.value === 'true';
        }

        if (Object.keys(payload).length === 0) {
            showToast('Check at least one field to update in PATCH payload', 'warning', 2500);
            return;
        }

        try {
            showToast('Sending PATCH update...', 'info', 1500);
            const res = await updateUser(this.currentUser.id, payload);
            if (res.ok) {
                showToast('✓ User updated successfully!', 'success', 2500);
                this.loadProfile(false);
                this.loadDirectory();
            } else {
                showToast(`Update rejected: ${res.data?.error?.message || res.status}`, 'danger', 3500);
            }
        } catch (err) {
            showToast(`Update error: ${err.message}`, 'danger', 3500);
        }
    }

    async handleTestRbac() {
        showToast('Testing Casbin RBAC Authorization...', 'info', 2000);
        try {
            const res = await listUsers(1, 10);
            if (res.status === 403) {
                showToast('🛡️ Casbin RBAC Verified: 403 Forbidden! Non-admin is correctly denied.', 'warning', 4500);
            } else if (res.ok) {
                showToast('Action allowed (Your current token has permission for this resource).', 'success', 3000);
            } else {
                showToast(`Server returned status: ${res.status}`, 'info', 2500);
            }
        } catch (err) {
            showToast(`RBAC Test result: ${err.message}`, 'info', 3000);
        }
    }

    async handleDeactivate() {
        if (!this.currentUser) return;
        if (!confirm(`Are you sure you want to deactivate account (${this.currentUser.email})? All sessions will be revoked immediately.`)) {
            return;
        }

        try {
            showToast('Deactivating account...', 'warning', 2000);
            const res = await updateUser(this.currentUser.id, { is_active: false });
            if (res.ok) {
                showToast('✓ Account deactivated. Clearing sessions...', 'danger', 3500);
                sessionStore.clearAllSessions();
                setTimeout(() => window.location.reload(), 1500);
            } else {
                showToast(`Deactivation rejected: ${res.data?.error?.message || res.status}`, 'danger', 3500);
            }
        } catch (err) {
            showToast(`Deactivation error: ${err.message}`, 'danger', 3500);
        }
    }

    async loadDirectory() {
        const tbody = document.getElementById('tbody-user-directory');
        const indicator = document.getElementById('dir-page-indicator');
        const prevBtn = document.getElementById('btn-dir-prev');
        const nextBtn = document.getElementById('btn-dir-next');

        if (!tbody) return;

        try {
            const res = await listUsers(this.directoryPage, this.directoryPageSize);
            if (res.status === 403) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="7" class="text-center p-4">
                            <div class="diagnostic-card d-inline-block text-left" style="max-width: 500px; margin: 0 auto;">
                                <h4>🛡️ 403 ACCESS_DENIED — Casbin RBAC Guard</h4>
                                <p class="text-xs">Only administrators can list users in the directory. Standard users are denied with 403.</p>
                            </div>
                        </td>
                    </tr>
                `;
                return;
            }

            if (res.ok && res.data) {
                const items = Array.isArray(res.data) ? res.data : (res.data.items || []);

                if (items.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No users found.</td></tr>';
                    return;
                }

                tbody.innerHTML = items.map(u => `
                    <tr>
                        <td class="font-mono text-xs">${escapeHtml(String(u.id))}</td>
                        <td class="bold">${escapeHtml(u.email)}</td>
                        <td>${escapeHtml(u.name || '-')}</td>
                        <td>${renderBadge(u.role === 'admin' ? 'danger' : 'info', u.role || 'user')}</td>
                        <td>${renderBadge(u.is_active ? 'success' : 'danger', u.is_active ? 'Active' : 'Inactive')}</td>
                        <td>${renderBadge(u.is_verified ? 'success' : 'warning', u.is_verified ? 'Yes' : 'No')}</td>
                        <td class="font-mono text-xs">${formatDate(u.created_at)}</td>
                    </tr>
                `).join('');

                if (indicator) indicator.textContent = `Page ${this.directoryPage}`;
                if (prevBtn) prevBtn.disabled = this.directoryPage <= 1;
                if (nextBtn) nextBtn.disabled = items.length < this.directoryPageSize;
            } else {
                tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Failed to load directory (Status ${res.status})</td></tr>`;
            }
        } catch (err) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Error: ${escapeHtml(err.message)}</td></tr>`;
        }
    }
}
