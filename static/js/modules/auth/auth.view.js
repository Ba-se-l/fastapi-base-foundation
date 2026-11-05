/**
 * Authentication & Dual-Device Lineage Workbench View
 * Provides:
 * 1. 1-Click Demo Setup (Creates account, logs into Device A & B concurrently)
 * 2. Visual Device A vs Device B token cards with full unclipped JWT claims (sub, fid, jti, sec_ver, exp)
 * 3. Memory Token Vault active indicator
 * 4. Token Rotation trigger per device
 * 5. Token Replay Attack Simulator (tests family invalidation and isolation)
 * 6. Logout, Logout-all, and Password Change controls
 */
import { register, login, refreshToken, logout, logoutAll, changePassword } from './auth.api.js';
import { sessionStore } from '../../core/session-store.js';
import { formatTimeRemaining } from '../../core/jwt-decoder.js';
import { showToast, escapeHtml } from '../../shared/ui-helpers.js';
import { eventBus } from '../../core/event-emitter.js';

export class AuthView {
    constructor() {
        this.unsubscribe = null;
    }

    render() {
        const activeSlot = sessionStore.getActiveSlot();
        const sessionA = sessionStore.getSession('device_a');
        const sessionB = sessionStore.getSession('device_b');
        const replay = sessionStore.getReplayBuffer();

        return `
            <div class="module-card">
                <div class="card-header">
                    <div class="header-title">
                        <h2>Authentication & Multi-Device Lineage</h2>
                        <span class="subtitle">Dual concurrent virtual devices, Argon2id validation, token rotation, smart device isolation, and replay detection</span>
                    </div>
                    <div class="header-actions">
                        <button class="btn btn-warning" id="btn-1click-demo" title="Auto-registers test user and logs in to Device A and Device B simultaneously">
                            🚀 1-Click Demo Setup
                        </button>
                        <button class="btn btn-outline btn-danger" id="btn-clear-sessions">
                            Clear All Sessions
                        </button>
                    </div>
                </div>

                <!-- Active Slot Selector -->
                <div class="device-selector-bar">
                    <span class="selector-label">Active HTTP Client Target:</span>
                    <button class="device-pill ${activeSlot === 'device_a' ? 'active' : ''}" data-slot="device_a" id="pill-device-a">
                        📱 Device A (Laptop / Workstation)
                    </button>
                    <button class="device-pill ${activeSlot === 'device_b' ? 'active' : ''}" data-slot="device_b" id="pill-device-b">
                        📱 Device B (Mobile / Remote)
                    </button>
                </div>

                <!-- Dual Device Grid (Fluid clamp, no clipping) -->
                <div class="devices-grid">
                    <!-- Device A Card -->
                    <div class="device-card ${activeSlot === 'device_a' ? 'is-active-device' : ''}" id="card-device-a">
                        <div class="device-card-header">
                            <div class="device-name">
                                <span class="device-badge">Device A</span>
                                <h3>Laptop Workstation</h3>
                            </div>
                            <span class="device-status ${sessionA ? 'status-online' : 'status-offline'}">
                                ${sessionA ? '● Authenticated' : '○ Logged Out'}
                            </span>
                        </div>
                        <div class="device-body">
                            ${this._renderDeviceContent('device_a', sessionA)}
                        </div>
                    </div>

                    <!-- Device B Card -->
                    <div class="device-card ${activeSlot === 'device_b' ? 'is-active-device' : ''}" id="card-device-b">
                        <div class="device-card-header">
                            <div class="device-name">
                                <span class="device-badge badge-purple">Device B</span>
                                <h3>Mobile Device</h3>
                            </div>
                            <span class="device-status ${sessionB ? 'status-online' : 'status-offline'}">
                                ${sessionB ? '● Authenticated' : '○ Logged Out'}
                            </span>
                        </div>
                        <div class="device-body">
                            ${this._renderDeviceContent('device_b', sessionB)}
                        </div>
                    </div>
                </div>

                <!-- Replay Attack Simulator Panel -->
                <div class="card-section mt-4">
                    <div class="section-header-row">
                        <div>
                            <h3>Token Family Replay Attack Simulator</h3>
                            <p class="section-desc">When a refresh token is rotated, the old token becomes a tombstone. If an attacker replays the old token, the backend detects theft, invalidates the family, and leaves other devices intact.</p>
                        </div>
                        <div class="replay-actions">
                            <button class="btn btn-danger" id="btn-trigger-replay" ${!replay ? 'disabled' : ''}>
                                ⚠️ Execute Replay Attack on Rotated Token
                            </button>
                        </div>
                    </div>

                    <div class="replay-status-box" id="replay-status-box">
                        ${this._renderReplayStatus(replay)}
                    </div>
                </div>

                <!-- Manual Operations & Password Change -->
                <div class="card-section mt-4">
                    <h3>Manual Credential Operations (Targeting ${activeSlot === 'device_a' ? 'Device A' : 'Device B'})</h3>
                    <div class="grid-3">
                        <!-- Login Form -->
                        <div class="card">
                            <h4>Login to ${activeSlot === 'device_a' ? 'Device A' : 'Device B'}</h4>
                            <form id="form-login">
                                <div class="form-group">
                                    <label>Email Address</label>
                                    <input type="email" id="login-email" class="form-input" placeholder="user@example.com" required value="admin@example.com">
                                </div>
                                <div class="form-group">
                                    <label>Password</label>
                                    <input type="password" id="login-password" class="form-input" placeholder="••••••••" required value="SecureAdmin@2026!">
                                </div>
                                <button type="submit" class="btn btn-primary w-100" id="btn-login-submit">Login</button>
                            </form>
                        </div>

                        <!-- Register Form -->
                        <div class="card">
                            <h4>Register New User</h4>
                            <form id="form-register">
                                <div class="form-group">
                                    <label>Full Name</label>
                                    <input type="text" id="reg-name" class="form-input" placeholder="Jane Doe" required value="Test Engineer">
                                </div>
                                <div class="form-group">
                                    <label>Email Address</label>
                                    <input type="email" id="reg-email" class="form-input" placeholder="engineer@example.com" required value="user_${Date.now().toString().slice(-4)}@example.com">
                                </div>
                                <div class="form-group">
                                    <label>Password (Argon2id)</label>
                                    <input type="password" id="reg-password" class="form-input" placeholder="Min 8 chars" required value="StrongP@ssw0rd!2026">
                                </div>
                                <button type="submit" class="btn btn-secondary w-100" id="btn-register-submit">Register Account</button>
                            </form>
                        </div>

                        <!-- Change Password Form -->
                        <div class="card">
                            <h4>Change Password (Security Ver Bump)</h4>
                            <form id="form-change-password">
                                <div class="form-group">
                                    <label>Current Password</label>
                                    <input type="password" id="pwd-current" class="form-input" placeholder="••••••••" required value="SecureAdmin@2026!">
                                </div>
                                <div class="form-group">
                                    <label>New Password</label>
                                    <input type="password" id="pwd-new" class="form-input" placeholder="Min 8 chars, 1 uppercase" required value="NewSecureP@ss2026!">
                                </div>
                                <button type="submit" class="btn btn-warning w-100" id="btn-change-password-submit">Update Password</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    _renderDeviceContent(slot, session) {
        if (!session) {
            return `
                <div class="empty-state">
                    <p>No active token session for this device slot.</p>
                    <p class="text-muted">Use <strong>1-Click Demo Setup</strong> or Login below to populate credentials.</p>
                </div>
            `;
        }

        const access = session.accessClaims || {};
        const refresh = session.refreshClaims || {};

        return `
            <div class="claims-summary">
                <div class="mb-2">
                    <span class="badge badge-success" title="Tokens kept in ES module memory; sessionStorage stores redacted markers">
                        🔒 Memory Token Vault: Active
                    </span>
                </div>
                <div class="claims-grid">
                    <div class="claim-row">
                        <span class="claim-label">Subject (User ID):</span>
                        <span class="claim-val breakable-mono">${escapeHtml(access.sub || '-')}</span>
                    </div>
                    <div class="claim-row">
                        <span class="claim-label">Family ID (fid):</span>
                        <span class="claim-val breakable-mono badge badge-info">${escapeHtml(refresh.fid || access.fid || 'None')}</span>
                    </div>
                    <div class="claim-row">
                        <span class="claim-label">Security Version (sec_ver):</span>
                        <span class="claim-val bold">${escapeHtml(access.sec_ver ?? refresh.sec_ver ?? 1)}</span>
                    </div>
                    <div class="claim-row">
                        <span class="claim-label">Refresh JTI:</span>
                        <span class="claim-val breakable-mono">${escapeHtml(refresh.jti || '-')}</span>
                    </div>
                    <div class="claim-row">
                        <span class="claim-label">Access Expiry:</span>
                        <span class="claim-val">${formatTimeRemaining(access.exp)}</span>
                    </div>
                    <div class="claim-row">
                        <span class="claim-label">Refresh Expiry:</span>
                        <span class="claim-val">${formatTimeRemaining(refresh.exp)}</span>
                    </div>
                </div>
            </div>

            <div class="device-actions-row">
                <button class="btn btn-sm btn-outline btn-rotate" data-slot="${slot}" title="Rotates refresh token and saves previous token to replay buffer">
                    🔄 Rotate Token
                </button>
                <button class="btn btn-sm btn-outline btn-logout" data-slot="${slot}">
                    Logout Device
                </button>
                <button class="btn btn-sm btn-danger btn-logout-all" data-slot="${slot}" title="Invalidates all sessions across all devices for this user">
                    Logout All Devices
                </button>
            </div>
        `;
    }

    _renderReplayStatus(replay) {
        if (!replay) {
            return `
                <div class="empty-state-small">
                    <span>No stale token captured yet. Click <strong>"Rotate Token"</strong> on Device A or B above to capture a replay candidate.</span>
                </div>
            `;
        }
        return `
            <div class="card p-3">
                <div class="d-flex align-items-center gap-2 flex-wrap">
                    <span class="badge badge-warning">Stale Token Armed</span>
                    <span>Captured from <strong>${replay.deviceSlot === 'device_b' ? 'Device B' : 'Device A'}</strong> at ${new Date(replay.capturedAt).toLocaleTimeString()}</span>
                    <span>Family ID: <code class="breakable-mono">${escapeHtml(replay.previousFid || 'N/A')}</code></span>
                    <span>Previous JTI: <code class="breakable-mono">${escapeHtml(replay.previousJti || 'N/A')}</code></span>
                </div>
            </div>
        `;
    }

    bindEvents() {
        if (this.unsubscribe) this.unsubscribe();
        this.unsubscribe = eventBus.on('session:changed', () => {
            this.updateView();
        });

        // 1-Click Demo
        const demoBtn = document.getElementById('btn-1click-demo');
        if (demoBtn) {
            demoBtn.addEventListener('click', () => this.handle1ClickDemo());
        }

        // Clear All Sessions
        const clearBtn = document.getElementById('btn-clear-sessions');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                sessionStore.clearAllSessions();
                showToast('All local device sessions cleared', 'info', 2000);
            });
        }

        // Slot Switchers
        const pillA = document.getElementById('pill-device-a');
        const pillB = document.getElementById('pill-device-b');
        if (pillA) {
            pillA.addEventListener('click', () => {
                sessionStore.setActiveSlot('device_a');
                showToast('Active HTTP client switched to Device A', 'info', 1500);
            });
        }
        if (pillB) {
            pillB.addEventListener('click', () => {
                sessionStore.setActiveSlot('device_b');
                showToast('Active HTTP client switched to Device B', 'info', 1500);
            });
        }

        // Action Buttons inside device cards
        document.querySelectorAll('.btn-rotate').forEach(btn => {
            btn.addEventListener('click', () => {
                const slot = btn.dataset.slot;
                this.handleRotate(slot);
            });
        });

        document.querySelectorAll('.btn-logout').forEach(btn => {
            btn.addEventListener('click', () => {
                const slot = btn.dataset.slot;
                this.handleLogout(slot);
            });
        });

        document.querySelectorAll('.btn-logout-all').forEach(btn => {
            btn.addEventListener('click', () => {
                this.handleLogoutAll();
            });
        });

        // Replay Trigger
        const replayBtn = document.getElementById('btn-trigger-replay');
        if (replayBtn) {
            replayBtn.addEventListener('click', () => this.handleReplayAttack());
        }

        // Login Form
        const loginForm = document.getElementById('form-login');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleManualLogin();
            });
        }

        // Register Form
        const regForm = document.getElementById('form-register');
        if (regForm) {
            regForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleManualRegister();
            });
        }

        // Change Password Form
        const pwdForm = document.getElementById('form-change-password');
        if (pwdForm) {
            pwdForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleChangePassword();
            });
        }
    }

    cleanup() {
        if (this.unsubscribe) {
            this.unsubscribe();
            this.unsubscribe = null;
        }
    }

    updateView() {
        const viewport = document.getElementById('workspace-viewport');
        if (viewport) {
            viewport.innerHTML = this.render();
            this.bindEvents();
        }
    }

    async handle1ClickDemo() {
        showToast('Initiating 1-Click Multi-Device Demo Setup...', 'info', 2000);
        const email = `demo_${Date.now().toString().slice(-4)}@enterprise.io`;
        const password = 'DemoP@ssword2026!';
        const name = 'Dual Device Demo User';

        // 1. Register User
        const regRes = await register({ email, password, name });
        if (!regRes.ok) {
            showToast(`Registration failed: ${regRes.data?.error?.message || 'Error'}`, 'error');
            return;
        }

        // 2. Login Device A
        const loginA = await login({ email, password });
        if (loginA.ok && loginA.data) {
            sessionStore.setSession('device_a', {
                accessToken: loginA.data.access_token,
                refreshToken: loginA.data.refresh_token,
                user: { email, name }
            });
        }

        // 3. Login Device B
        const loginB = await login({ email, password });
        if (loginB.ok && loginB.data) {
            sessionStore.setSession('device_b', {
                accessToken: loginB.data.access_token,
                refreshToken: loginB.data.refresh_token,
                user: { email, name }
            });
        }

        showToast('✓ Device A and Device B authenticated concurrently with unique family lineage!', 'success', 3500);
    }

    async handleManualLogin() {
        const activeSlot = sessionStore.getActiveSlot();
        const email = document.getElementById('login-email')?.value;
        const password = document.getElementById('login-password')?.value;

        const res = await login({ email, password });
        if (res.ok && res.data) {
            sessionStore.setSession(activeSlot, {
                accessToken: res.data.access_token,
                refreshToken: res.data.refresh_token,
                user: { email }
            });
            showToast(`✓ Logged in successfully to ${activeSlot === 'device_b' ? 'Device B' : 'Device A'}!`, 'success');
        } else {
            showToast(`Login failed: ${res.data?.error?.message || 'Invalid credentials'}`, 'error');
        }
    }

    async handleManualRegister() {
        const name = document.getElementById('reg-name')?.value;
        const email = document.getElementById('reg-email')?.value;
        const password = document.getElementById('reg-password')?.value;

        const res = await register({ name, email, password });
        if (res.ok) {
            showToast('✓ Account registered! You can now log in.', 'success', 3000);
            const loginEmail = document.getElementById('login-email');
            if (loginEmail) loginEmail.value = email;
        } else {
            showToast(`Registration failed: ${res.data?.error?.message || 'Validation error'}`, 'error');
        }
    }

    async handleChangePassword() {
        const current_password = document.getElementById('pwd-current')?.value;
        const new_password = document.getElementById('pwd-new')?.value;

        const res = await changePassword({ current_password, new_password });
        if (res.ok) {
            showToast('✓ Password updated! Security version incremented and all sessions revoked.', 'success', 4000);
            sessionStore.clearAllSessions();
        } else {
            showToast(`Password change failed: ${res.data?.error?.message || 'Error'}`, 'error');
        }
    }

    async handleRotate(slot) {
        const session = sessionStore.getSession(slot);
        if (!session?.refreshToken) {
            showToast('No active refresh token to rotate', 'warning');
            return;
        }

        const oldRefresh = session.refreshToken;
        const oldFid = session.refreshClaims?.fid;
        const oldJti = session.refreshClaims?.jti;

        const res = await refreshToken(oldRefresh);
        if (res.ok && res.data) {
            // Save old token to replay buffer
            sessionStore.setReplayBuffer({
                token: oldRefresh,
                deviceSlot: slot,
                previousFid: oldFid,
                previousJti: oldJti,
                capturedAt: Date.now()
            });

            // Update session with rotated tokens
            sessionStore.setSession(slot, {
                ...session,
                accessToken: res.data.access_token,
                refreshToken: res.data.refresh_token
            });

            showToast(`✓ Token rotated on ${slot}! Previous token saved to Replay Buffer.`, 'success', 3500);
        } else {
            showToast(`Rotation failed: ${res.data?.error?.message || 'Invalid token'}`, 'error');
        }
    }

    async handleReplayAttack() {
        const replay = sessionStore.getReplayBuffer();
        if (!replay?.token) {
            showToast('No stale token armed in replay buffer', 'warning');
            return;
        }

        showToast('Simulating Replay Attack by sending stale tombstone token...', 'warning', 2500);
        const res = await refreshToken(replay.token);

        if (res.status === 401 && res.data?.error?.code === 'TOKEN_REVOKED') {
            showToast('🛡️ Replay Detection Triggered! 401 TOKEN_REVOKED. Compromised family destroyed.', 'error', 4500);
            // Invalidate the attacked slot locally
            sessionStore.removeSession(replay.deviceSlot);
            sessionStore.clearReplayBuffer();
        } else {
            showToast(`Replay attack unexpected response: status ${res.status}`, 'info');
        }
    }

    async handleLogout(slot) {
        const session = sessionStore.getSession(slot);
        if (session?.refreshToken) {
            await logout(session.refreshToken);
        }
        sessionStore.removeSession(slot);
        showToast(`Logged out from ${slot}`, 'info');
    }

    async handleLogoutAll() {
        const activeSlot = sessionStore.getActiveSlot();
        const session = sessionStore.getSession(activeSlot);
        if (session?.accessToken) {
            await logoutAll();
        }
        sessionStore.clearAllSessions();
        showToast('✓ Global logout executed across all devices!', 'info');
    }
}
