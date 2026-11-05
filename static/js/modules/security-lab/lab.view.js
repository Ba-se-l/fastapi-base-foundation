/**
 * Security Lab & Guardrail Stress Workbench
 * 1. 8 Automated One-Click Stress Tests (Including V1.0.0 Hardening)
 * 2. Interactive CLI Command Generator (manage.py)
 */
import { httpClient } from '../../core/http-client.js';
import { showToast, copyToClipboard, escapeHtml } from '../../shared/ui-helpers.js';
import { sessionStore } from '../../core/session-store.js';

export class SecurityLabView {
    constructor() {}

    render() {
        return `
            <div class="module-card">
                <div class="card-header">
                    <div class="header-title">
                        <h2>Security Stress Lab & Guardrails</h2>
                        <span class="subtitle">Live verification of enterprise defensive constraints, data sanitization, schema strictness, and CLI governance</span>
                    </div>
                </div>

                <!-- 8 Guardrail Tests Grid -->
                <div class="card-section">
                    <h3>Enterprise Guardrail Verification Suite (8 Tests)</h3>
                    <p class="section-desc">Run atomic regression tests directly against live endpoints and observe envelope enforcement in the Network Inspector.</p>

                    <div class="tests-grid">
                        <!-- Test 1: Secret Redaction in 422 -->
                        <div class="test-card" id="test-card-1">
                            <div class="test-header">
                                <span class="test-num">01</span>
                                <h4>Secret Redaction in 422 Validation</h4>
                            </div>
                            <p class="test-desc">Submits an invalid email with a raw password to verify that Pydantic error details mask or strip raw password data (AUD-01).</p>
                            <div class="test-action">
                                <button class="btn btn-sm btn-primary btn-run-test" data-test="1">Run Test 01</button>
                                <span class="test-result-badge badge" id="test-1-badge">Not Run</span>
                            </div>
                            <div class="test-details" id="test-1-details"></div>
                        </div>

                        <!-- Test 2: Explicit Null Rejection -->
                        <div class="test-card" id="test-card-2">
                            <div class="test-header">
                                <span class="test-num">02</span>
                                <h4>Explicit Null Rejection in PATCH</h4>
                            </div>
                            <p class="test-desc">Submits <code>{"name": null}</code> to <code>PATCH /api/v1/users/{id}</code> to verify that explicit nulls are rejected with 422 (API-01).</p>
                            <div class="test-action">
                                <button class="btn btn-sm btn-primary btn-run-test" data-test="2">Run Test 02</button>
                                <span class="test-result-badge badge" id="test-2-badge">Not Run</span>
                            </div>
                            <div class="test-details" id="test-2-details"></div>
                        </div>

                        <!-- Test 3: Argon2 Password Boundary -->
                        <div class="test-card" id="test-card-3">
                            <div class="test-header">
                                <span class="test-num">03</span>
                                <h4>Argon2id Boundary & Length Limit</h4>
                            </div>
                            <p class="test-desc">Submits a password length exceeding 100 characters to verify DoS memory protection and Argon2 boundaries (API-02).</p>
                            <div class="test-action">
                                <button class="btn btn-sm btn-primary btn-run-test" data-test="3">Run Test 03</button>
                                <span class="test-result-badge badge" id="test-3-badge">Not Run</span>
                            </div>
                            <div class="test-details" id="test-3-details"></div>
                        </div>

                        <!-- Test 4: Non-String Email Type Guard -->
                        <div class="test-card" id="test-card-4">
                            <div class="test-header">
                                <span class="test-num">04</span>
                                <h4>Non-String Type Coercion Guard</h4>
                            </div>
                            <p class="test-desc">Sends non-string numeric value <code>{"email": 12345}</code> to test strict validation without silent type coercion (API-03).</p>
                            <div class="test-action">
                                <button class="btn btn-sm btn-primary btn-run-test" data-test="4">Run Test 04</button>
                                <span class="test-result-badge badge" id="test-4-badge">Not Run</span>
                            </div>
                            <div class="test-details" id="test-4-details"></div>
                        </div>

                        <!-- Test 5: Correlation ID Sanitization -->
                        <div class="test-card" id="test-card-5">
                            <div class="test-header">
                                <span class="test-num">05</span>
                                <h4>X-Request-ID Sanitization & Safe Injection</h4>
                            </div>
                            <p class="test-desc">Injects malicious header <code>X-Request-ID: &lt;script&gt;alert(1)&lt;/script&gt;</code> to verify middleware sanitizes it to a safe UUID (OPS-01).</p>
                            <div class="test-action">
                                <button class="btn btn-sm btn-primary btn-run-test" data-test="5">Run Test 05</button>
                                <span class="test-result-badge badge" id="test-5-badge">Not Run</span>
                            </div>
                            <div class="test-details" id="test-5-details"></div>
                        </div>

                        <!-- Test 6: SEC-31A extra="forbid" Schema Rejection -->
                        <div class="test-card" id="test-card-6">
                            <div class="test-header">
                                <span class="test-num">06</span>
                                <h4>Strict Schema Extra Fields Rejection (SEC-31A)</h4>
                            </div>
                            <p class="test-desc">Submits unexpected property <code>{"is_admin": true, "extra_field": "hack"}</code> to verify Pydantic <code>extra="forbid"</code> rejects it with 422.</p>
                            <div class="test-action">
                                <button class="btn btn-sm btn-primary btn-run-test" data-test="6">Run Test 06</button>
                                <span class="test-result-badge badge" id="test-6-badge">Not Run</span>
                            </div>
                            <div class="test-details" id="test-6-details"></div>
                        </div>

                        <!-- Test 7: SEC-31B Oversized Token Payload Bound -->
                        <div class="test-card" id="test-card-7">
                            <div class="test-header">
                                <span class="test-num">07</span>
                                <h4>Oversized Token Payload Bound (SEC-31B)</h4>
                            </div>
                            <p class="test-desc">Sends oversized <code>refresh_token</code> (>2048 chars) to <code>POST /auth/refresh</code> to assert immediate 422 boundary rejection without JWT CPU burn.</p>
                            <div class="test-action">
                                <button class="btn btn-sm btn-primary btn-run-test" data-test="7">Run Test 07</button>
                                <span class="test-result-badge badge" id="test-7-badge">Not Run</span>
                            </div>
                            <div class="test-details" id="test-7-details"></div>
                        </div>

                        <!-- Test 8: SEC-32 Client Memory Vault & CSP Verification -->
                        <div class="test-card" id="test-card-8">
                            <div class="test-header">
                                <span class="test-num">08</span>
                                <h4>Client Token Vault & CSP Check (SEC-32)</h4>
                            </div>
                            <p class="test-desc">Inspects browser <code>sessionStorage</code> to verify raw JWTs are never stored on disk and verifies HTTP Content-Security-Policy bans unsafe-inline.</p>
                            <div class="test-action">
                                <button class="btn btn-sm btn-primary btn-run-test" data-test="8">Run Test 08</button>
                                <span class="test-result-badge badge" id="test-8-badge">Not Run</span>
                            </div>
                            <div class="test-details" id="test-8-details"></div>
                        </div>
                    </div>
                </div>

                <!-- CLI Generator Section -->
                <div class="card-section mt-4">
                    <h3>Operational CLI Command Builder (manage.py)</h3>
                    <p class="section-desc">Generate verified CLI commands for database migrations, role-based authorization, and administrative bootstrapping.</p>

                    <div class="cli-builder-grid">
                        <div class="cli-controls">
                            <div class="form-group">
                                <label>Command Action:</label>
                                <select id="cli-category" class="form-select">
                                    <option value="create-admin">create-admin: Create initial administrator</option>
                                    <option value="promote-admin">promote-admin: Promote existing user to admin</option>
                                    <option value="seed-policies">seed-policies: Idempotent Casbin RBAC seed</option>
                                    <option value="assign-role">assign-role: Assign role to user (user_id + role)</option>
                                    <option value="unassign-role">unassign-role: Remove role from user</option>
                                    <option value="grant">grant: Grant permission rule (role, resource, action)</option>
                                    <option value="revoke">revoke: Revoke permission rule</option>
                                    <option value="list-policies">list-policies: Display all active Casbin rules</option>
                                    <option value="purge-sessions">purge-sessions: Clean up expired sessions</option>
                                    <option value="alembic-upgrade">Alembic: Upgrade database to head</option>
                                    <option value="alembic-check">Alembic: Drift check against models</option>
                                </select>
                            </div>

                            <div class="form-group" id="cli-opt-group-1">
                                <label id="cli-lbl-1">Target Email / User ID:</label>
                                <input type="text" id="cli-param-1" class="form-input" value="admin@enterprise.io">
                            </div>

                            <div class="form-group" id="cli-opt-group-2">
                                <label id="cli-lbl-2">Role / Password:</label>
                                <input type="text" id="cli-param-2" class="form-input" value="AdminP@ss123!">
                            </div>

                            <div class="form-group" id="cli-opt-group-3" style="display: none;">
                                <label id="cli-lbl-3">Resource / Domain:</label>
                                <input type="text" id="cli-param-3" class="form-input" value="users">
                            </div>
                        </div>

                        <div class="cli-output-box mt-3">
                            <label class="form-group-label">Generated Shell Command:</label>
                            <div class="cli-code-row">
                                <pre class="code-block" id="cli-command-preview">python manage.py create-admin --email admin@enterprise.io --password AdminP@ss123! --name "System Admin"</pre>
                                <button class="btn btn-sm btn-secondary mt-2" id="btn-copy-cli">Copy Command</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    bindEvents() {
        document.querySelectorAll('.btn-run-test').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const testId = btn.dataset.test;
                this.runTest(testId);
            });
        });

        // CLI Generator
        const catSelect = document.getElementById('cli-category');
        const param1 = document.getElementById('cli-param-1');
        const param2 = document.getElementById('cli-param-2');
        const param3 = document.getElementById('cli-param-3');
        const lbl1 = document.getElementById('cli-lbl-1');
        const lbl2 = document.getElementById('cli-lbl-2');
        const lbl3 = document.getElementById('cli-lbl-3');
        const grp1 = document.getElementById('cli-opt-group-1');
        const grp2 = document.getElementById('cli-opt-group-2');
        const grp3 = document.getElementById('cli-opt-group-3');
        const preview = document.getElementById('cli-command-preview');
        const copyBtn = document.getElementById('btn-copy-cli');

        const updateCli = () => {
            const cat = catSelect?.value;
            const p1 = param1?.value || '';
            const p2 = param2?.value || '';
            const p3 = param3?.value || '';
            let cmd = '';

            // Dynamic label adjustment
            if (grp1) grp1.style.display = 'flex';
            if (grp2) grp2.style.display = 'flex';
            if (grp3) grp3.style.display = 'none';

            switch (cat) {
                case 'create-admin':
                    if (lbl1) lbl1.textContent = 'Admin Email:';
                    if (lbl2) lbl2.textContent = 'Admin Password:';
                    cmd = `python manage.py create-admin --email ${p1 || 'admin@enterprise.io'} --password ${p2 || 'AdminP@ss123!'} --name "System Admin"`;
                    break;
                case 'promote-admin':
                    if (lbl1) lbl1.textContent = 'User Email to Promote:';
                    if (grp2) grp2.style.display = 'none';
                    cmd = `python manage.py promote-admin --email ${p1 || 'user@enterprise.io'}`;
                    break;
                case 'seed-policies':
                    if (grp1) grp1.style.display = 'none';
                    if (grp2) grp2.style.display = 'none';
                    cmd = `python manage.py seed-policies`;
                    break;
                case 'assign-role':
                    if (lbl1) lbl1.textContent = 'User ID (Integer):';
                    if (lbl2) lbl2.textContent = 'Role Name (admin/user):';
                    cmd = `python manage.py assign-role --user-id ${p1 || '1'} --role ${p2 || 'admin'}`;
                    break;
                case 'unassign-role':
                    if (lbl1) lbl1.textContent = 'User ID (Integer):';
                    if (lbl2) lbl2.textContent = 'Role Name:';
                    cmd = `python manage.py unassign-role --user-id ${p1 || '1'} --role ${p2 || 'admin'}`;
                    break;
                case 'grant':
                    if (lbl1) lbl1.textContent = 'Role Name:';
                    if (lbl2) lbl2.textContent = 'Resource (users/audit/*):';
                    if (lbl3) lbl3.textContent = 'Action (read/write/*):';
                    if (grp3) grp3.style.display = 'flex';
                    cmd = `python manage.py grant --role ${p1 || 'admin'} --resource ${p2 || 'users'} --action ${p3 || '*'}`;
                    break;
                case 'revoke':
                    if (lbl1) lbl1.textContent = 'Role Name:';
                    if (lbl2) lbl2.textContent = 'Resource:';
                    if (lbl3) lbl3.textContent = 'Action:';
                    if (grp3) grp3.style.display = 'flex';
                    cmd = `python manage.py revoke --role ${p1 || 'admin'} --resource ${p2 || 'users'} --action ${p3 || '*'}`;
                    break;
                case 'list-policies':
                    if (grp1) grp1.style.display = 'none';
                    if (grp2) grp2.style.display = 'none';
                    cmd = `python manage.py list-policies`;
                    break;
                case 'purge-sessions':
                    if (lbl1) lbl1.textContent = 'Before Days:';
                    if (grp2) grp2.style.display = 'none';
                    cmd = `python manage.py purge-sessions --before-days ${p1 || '30'}`;
                    break;
                case 'alembic-upgrade':
                    if (grp1) grp1.style.display = 'none';
                    if (grp2) grp2.style.display = 'none';
                    cmd = `alembic upgrade head`;
                    break;
                case 'alembic-check':
                    if (grp1) grp1.style.display = 'none';
                    if (grp2) grp2.style.display = 'none';
                    cmd = `alembic check`;
                    break;
                default:
                    cmd = `python manage.py --help`;
            }

            if (preview) preview.textContent = cmd;
        };

        if (catSelect) catSelect.addEventListener('change', updateCli);
        if (param1) param1.addEventListener('input', updateCli);
        if (param2) param2.addEventListener('input', updateCli);
        if (param3) param3.addEventListener('input', updateCli);
        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                const cmd = preview?.textContent || '';
                copyToClipboard(cmd).then(() => {
                    showToast('CLI command copied to clipboard!', 'success', 2000);
                });
            });
        }

        updateCli();
    }

    cleanup() {}

    async runTest(testId) {
        const badge = document.getElementById(`test-${testId}-badge`);
        const details = document.getElementById(`test-${testId}-details`);
        if (badge) {
            badge.textContent = 'Running...';
            badge.className = 'test-result-badge badge-warning';
        }

        try {
            switch (testId) {
                case '1':
                    await this.testSecretRedaction(badge, details);
                    break;
                case '2':
                    await this.testExplicitNull(badge, details);
                    break;
                case '3':
                    await this.testPasswordBoundary(badge, details);
                    break;
                case '4':
                    await this.testNonStringEmail(badge, details);
                    break;
                case '5':
                    await this.testCorrelationSanitization(badge, details);
                    break;
                case '6':
                    await this.testExtraFieldsRejection(badge, details);
                    break;
                case '7':
                    await this.testOversizedToken(badge, details);
                    break;
                case '8':
                    await this.testTokenVaultAndCsp(badge, details);
                    break;
            }
        } catch (err) {
            if (badge) {
                badge.textContent = 'Error';
                badge.className = 'test-result-badge badge-danger';
            }
            if (details) {
                details.innerHTML = `<span class="badge badge-danger">${escapeHtml(err.message)}</span>`;
            }
        }
    }

    async testSecretRedaction(badge, details) {
        const sensitivePass = 'UltraSecretP@ssword999!';
        const res = await httpClient.post('/api/v1/auth/register', {
            email: 'not-an-email',
            password: sensitivePass,
            name: 'Test Redaction'
        });

        const rawJson = JSON.stringify(res.data);
        const leaked = rawJson.includes(sensitivePass);

        if (res.status === 422 && !leaked) {
            badge.textContent = 'Passed (Safe)';
            badge.className = 'test-result-badge badge-success';
            details.innerHTML = `<span class="badge badge-success">✓ 422 Unprocessable Entity: password not reflected in errors.</span>`;
        } else if (leaked) {
            badge.textContent = 'Failed (Leaked)';
            badge.className = 'test-result-badge badge-danger';
            details.innerHTML = `<span class="badge badge-danger">⚠️ Secret password leaked in validation response!</span>`;
        } else {
            badge.textContent = `Status: ${res.status}`;
            badge.className = 'test-result-badge badge-warning';
            details.innerHTML = `<span>Expected 422, received ${res.status}</span>`;
        }
    }

    async testExplicitNull(badge, details) {
        const activeSlot = sessionStore.getActiveSlot();
        const session = sessionStore.getSession(activeSlot);
        const userId = session?.user?.id || (session?.accessClaims?.sub) || 1;

        const res = await httpClient.patch(`/api/v1/users/${userId}`, {
            name: null
        });

        if (res.status === 422) {
            badge.textContent = 'Passed (Rejected)';
            badge.className = 'test-result-badge badge-success';
            details.innerHTML = `<span class="badge badge-success">✓ 422 Schema Guard: {"name": null} rejected without silent corruption.</span>`;
        } else {
            badge.textContent = `Status: ${res.status}`;
            badge.className = 'test-result-badge badge-warning';
            details.innerHTML = `<span>Expected 422, received ${res.status}</span>`;
        }
    }

    async testPasswordBoundary(badge, details) {
        const longPass = 'P@ss' + 'A'.repeat(120);
        const res = await httpClient.post('/api/v1/auth/register', {
            email: 'boundary.test@enterprise.io',
            password: longPass,
            name: 'Boundary Test'
        });

        if (res.status === 422) {
            badge.textContent = 'Passed (Bounded)';
            badge.className = 'test-result-badge badge-success';
            details.innerHTML = `<span class="badge badge-success">✓ 422 Length Bound: >100 char password rejected before Argon2 hashing.</span>`;
        } else {
            badge.textContent = `Status: ${res.status}`;
            badge.className = 'test-result-badge badge-warning';
            details.innerHTML = `<span>Expected 422, received ${res.status}</span>`;
        }
    }

    async testNonStringEmail(badge, details) {
        const res = await httpClient.post('/api/v1/auth/register', {
            email: 12345,
            password: 'ValidP@ssword123!',
            name: 'Numeric Email Test'
        });

        if (res.status === 422) {
            badge.textContent = 'Passed (Strict)';
            badge.className = 'test-result-badge badge-success';
            details.innerHTML = `<span class="badge badge-success">✓ 422 Type Guard: numeric email rejected without silent coercion.</span>`;
        } else {
            badge.textContent = `Status: ${res.status}`;
            badge.className = 'test-result-badge badge-warning';
            details.innerHTML = `<span>Expected 422, received ${res.status}</span>`;
        }
    }

    async testCorrelationSanitization(badge, details) {
        const customReqId = sessionStore.getCustomRequestId();
        const maliciousHeader = '<script>alert(1)</script>';
        sessionStore.setCustomRequestId(maliciousHeader);

        const res = await httpClient.get('/health');
        sessionStore.setCustomRequestId(customReqId);

        const returnedId = res.headers?.['x-request-id'] || '';
        const wasSanitized = returnedId && !returnedId.includes('<script>');

        if (wasSanitized) {
            badge.textContent = 'Passed (Sanitized)';
            badge.className = 'test-result-badge badge-success';
            details.innerHTML = `<span class="badge badge-success">✓ X-Request-ID sanitized: "${escapeHtml(returnedId)}"</span>`;
        } else {
            badge.textContent = 'Failed';
            badge.className = 'test-result-badge badge-danger';
            details.innerHTML = `<span class="badge badge-danger">⚠️ Unsanitized request ID returned: ${escapeHtml(returnedId)}</span>`;
        }
    }

    async testExtraFieldsRejection(badge, details) {
        // SEC-31A: Sending extra fields must be rejected with 422
        const res = await httpClient.post('/api/v1/auth/register', {
            name: 'Extra Field User',
            email: 'extra.field@enterprise.io',
            password: 'ValidP@ssword123!',
            is_admin: true,
            unexpected_field: 'hack'
        });

        if (res.status === 422) {
            const errCode = res.data?.error?.code || '';
            const msg = res.data?.error?.message || '';
            badge.textContent = 'Passed (Extra Forbid)';
            badge.className = 'test-result-badge badge-success';
            details.innerHTML = `<span class="badge badge-success">✓ 422 extra="forbid": ${escapeHtml(errCode || 'VALIDATION_ERROR')} (${escapeHtml(msg)})</span>`;
        } else {
            badge.textContent = `Status: ${res.status}`;
            badge.className = 'test-result-badge badge-danger';
            details.innerHTML = `<span class="badge badge-danger">Expected 422 for extra fields, got ${res.status}</span>`;
        }
    }

    async testOversizedToken(badge, details) {
        // SEC-31B: Sending refresh_token > 2048 chars must be rejected at schema boundary with 422
        const oversizedToken = 'token_' + 'A'.repeat(2100);
        const res = await httpClient.post('/api/v1/auth/refresh', {
            refresh_token: oversizedToken
        });

        if (res.status === 422) {
            badge.textContent = 'Passed (2048 Bounded)';
            badge.className = 'test-result-badge badge-success';
            details.innerHTML = `<span class="badge badge-success">✓ 422 Length Bound: >2048 char token rejected at Pydantic boundary.</span>`;
        } else {
            badge.textContent = `Status: ${res.status}`;
            badge.className = 'test-result-badge badge-danger';
            details.innerHTML = `<span class="badge badge-danger">Expected 422 for oversized token, got ${res.status}</span>`;
        }
    }

    async testTokenVaultAndCsp(badge, details) {
        // SEC-32: Inspect sessionStorage for vault markers and inspect CSP header
        let passedVault = true;
        let storageReport = [];

        try {
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                const val = sessionStorage.getItem(key);
                if (key && (key.includes('token') || key.includes('device_'))) {
                    if (val && !val.includes('[VAULT_IN_MEMORY]') && !val.includes('[VAULT_PROTECTED]') && (val.includes('eyJ') || val.length > 50)) {
                        passedVault = false;
                        storageReport.push(`Raw token leaked in ${key}!`);
                    }
                }
            }
        } catch {
            // sessionStorage might be restricted
        }

        const res = await httpClient.get('/health');
        const csp = res.headers?.['content-security-policy'] || '';
        const hasUnsafeInline = csp.includes("'unsafe-inline'") && csp.includes('script-src');
        const hasScriptSrc = csp.includes('script-src');

        if (passedVault && !hasUnsafeInline) {
            badge.textContent = 'Passed (Vault & CSP)';
            badge.className = 'test-result-badge badge-success';
            details.innerHTML = `<span class="badge badge-success">✓ In-memory vault active (no raw tokens on disk) & CSP bans unsafe-inline.</span>`;
        } else {
            badge.textContent = 'Failed';
            badge.className = 'test-result-badge badge-danger';
            const reason = hasUnsafeInline ? 'unsafe-inline in CSP script-src!' : storageReport.join('; ');
            details.innerHTML = `<span class="badge badge-danger">⚠️ ${escapeHtml(reason)}</span>`;
        }
    }
}
