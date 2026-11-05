/**
 * Audit Logging & Forensics View
 * Features:
 * - Filterable Audit Log Exploration (user_id, event_type, severity, outcome, page, size)
 * - Automatic empty-param stripping to prevent 422 errors
 * - Friendly 403 ACCESS_DENIED diagnostic card with 1-click copyable admin promotion command
 * - Unclipped full-width state diff visualizer (changes_payload / extra_data)
 * - Multi-Format Export Hub (JSON, TXT, Markdown) with in-browser preview and file download
 */
import { listAuditLogs, getAuditLog, exportAuditLogs } from './audit.api.js';
import { showToast, formatDate, escapeHtml, renderBadge, syntaxHighlightJson, copyToClipboard } from '../../shared/ui-helpers.js';
import { sessionStore } from '../../core/session-store.js';

export class AuditView {
    constructor() {
        this.page = 1;
        this.pageSize = 10;
        this.currentLogs = [];
        this.selectedLog = null;
    }

    render() {
        return `
            <div class="module-card">
                <div class="card-header">
                    <div class="header-title">
                        <h2>Audit Trail & Security Forensics</h2>
                        <span class="subtitle">Immutable record of mutation events, actor attribution, correlation IDs, and state diffs</span>
                    </div>
                    <div class="header-actions">
                        <button class="btn btn-primary" id="btn-audit-refresh">↻ Refresh Logs</button>
                    </div>
                </div>

                <!-- Filters Bar (Stripping empty params automatically) -->
                <div class="filter-toolbar">
                    <div class="filter-group">
                        <label>Event Type:</label>
                        <select id="filter-audit-event" class="form-select">
                            <option value="">All Events</option>
                            <option value="auth.login">auth.login</option>
                            <option value="auth.logout">auth.logout</option>
                            <option value="auth.refresh">auth.refresh</option>
                            <option value="auth.replay">auth.replay</option>
                            <option value="user.register">user.register</option>
                            <option value="user.update">user.update</option>
                            <option value="user.deactivate">user.deactivate</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Severity:</label>
                        <select id="filter-audit-severity" class="form-select">
                            <option value="">All Severities</option>
                            <option value="INFO">INFO</option>
                            <option value="WARNING">WARNING</option>
                            <option value="ERROR">ERROR</option>
                            <option value="CRITICAL">CRITICAL</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Outcome:</label>
                        <select id="filter-audit-outcome" class="form-select">
                            <option value="">All Outcomes</option>
                            <option value="SUCCESS">SUCCESS</option>
                            <option value="FAILURE">FAILURE</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>User ID:</label>
                        <input type="text" id="filter-audit-user-id" class="form-input" placeholder="User ID" style="max-width: 100px;">
                    </div>
                    <button class="btn btn-secondary" id="btn-apply-filters">Apply Filters</button>
                </div>

                <!-- 403 Forbidden Diagnostic Slot -->
                <div id="audit-403-diagnostic" style="display: none;" class="mb-3"></div>

                <!-- Split Workspace: Logs Table on Left, Diff / Details on Right -->
                <div class="audit-split-view">
                    <!-- Logs Table Panel -->
                    <div class="card p-0">
                        <div class="table-responsive">
                            <table class="data-table" id="table-audit-logs">
                                <thead>
                                    <tr>
                                        <th>Timestamp</th>
                                        <th>Event Type</th>
                                        <th>Severity</th>
                                        <th>Outcome</th>
                                        <th>Actor ID</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody id="tbody-audit-logs">
                                    <tr><td colspan="6" class="text-center text-muted">Loading audit trail...</td></tr>
                                </tbody>
                            </table>
                        </div>

                        <div class="card-header p-3 m-0" style="border-top: 1px solid var(--border-default);">
                            <button class="btn btn-sm btn-outline" id="btn-audit-prev" disabled>&larr; Prev</button>
                            <span id="audit-page-indicator" class="bold font-mono">Page 1</span>
                            <button class="btn btn-sm btn-outline" id="btn-audit-next">Next &rarr;</button>
                        </div>
                    </div>

                    <!-- Diff & Payload Inspector Panel (Zero Truncation) -->
                    <div class="card" id="audit-detail-panel">
                        <div class="empty-state">Select an audit log entry on the left to inspect state diff and metadata.</div>
                    </div>
                </div>

                <!-- Export Hub Section -->
                <div class="card-section mt-4">
                    <div class="section-header-row">
                        <div>
                            <h3>Audit Export Hub</h3>
                            <p class="section-desc">Generate compliance reports in JSON, Plaintext, or Markdown formats</p>
                        </div>
                        <div class="btn-group">
                            <button class="btn btn-outline" id="btn-export-json">📄 Export JSON</button>
                            <button class="btn btn-outline" id="btn-export-txt">📝 Export TXT</button>
                            <button class="btn btn-outline" id="btn-export-md">📑 Export Markdown</button>
                        </div>
                    </div>

                    <div class="card p-3 mt-2" id="export-preview-box" style="display: none;">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h4 id="export-preview-title" class="m-0">Export Preview</h4>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-primary" id="btn-download-export">⬇ Download File</button>
                                <button class="btn btn-sm btn-outline" id="btn-close-export">Close</button>
                            </div>
                        </div>
                        <pre class="code-block" id="export-preview-content"></pre>
                    </div>
                </div>
            </div>
        `;
    }

    bindEvents() {
        const refreshBtn = document.getElementById('btn-audit-refresh');
        const filterBtn = document.getElementById('btn-apply-filters');
        if (refreshBtn) refreshBtn.addEventListener('click', () => this.loadLogs());
        if (filterBtn) filterBtn.addEventListener('click', () => {
            this.page = 1;
            this.loadLogs();
        });

        const prevBtn = document.getElementById('btn-audit-prev');
        const nextBtn = document.getElementById('btn-audit-next');
        if (prevBtn) {
            prevBtn.addEventListener('click', () => {
                if (this.page > 1) {
                    this.page--;
                    this.loadLogs();
                }
            });
        }
        if (nextBtn) {
            nextBtn.addEventListener('click', () => {
                this.page++;
                this.loadLogs();
            });
        }

        // Export Buttons
        document.getElementById('btn-export-json')?.addEventListener('click', () => this.handleExport('json'));
        document.getElementById('btn-export-txt')?.addEventListener('click', () => this.handleExport('txt'));
        document.getElementById('btn-export-md')?.addEventListener('click', () => this.handleExport('markdown'));
        document.getElementById('btn-close-export')?.addEventListener('click', () => {
            const box = document.getElementById('export-preview-box');
            if (box) box.style.display = 'none';
        });

        this.loadLogs();
    }

    cleanup() {}

    async loadLogs() {
        const tbody = document.getElementById('tbody-audit-logs');
        const diagBox = document.getElementById('audit-403-diagnostic');
        if (!tbody) return;

        const eventType = document.getElementById('filter-audit-event')?.value;
        const severity = document.getElementById('filter-audit-severity')?.value;
        const outcome = document.getElementById('filter-audit-outcome')?.value;
        const userId = document.getElementById('filter-audit-user-id')?.value;

        const params = {
            page: this.page,
            size: this.pageSize,
        };
        if (eventType) params.event_type = eventType;
        if (severity) params.severity = severity;
        if (outcome) params.outcome = outcome;
        if (userId) params.user_id = userId;

        try {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Fetching audit records...</td></tr>';
            if (diagBox) diagBox.style.display = 'none';

            const res = await listAuditLogs(params);

            if (res.status === 403) {
                // Show friendly 403 Access Denied diagnostic card with promotion command
                const activeSlot = sessionStore.getActiveSlot();
                const session = sessionStore.getSession(activeSlot);
                const currentId = session?.user?.id || (session?.accessClaims?.sub) || '<user_id>';
                const promoCmd = `python manage.py assign-role --user-id ${currentId} --role admin`;

                if (diagBox) {
                    diagBox.innerHTML = `
                        <div class="diagnostic-card">
                            <h4>🛡️ 403 ACCESS_DENIED — Casbin Authorization Guard</h4>
                            <p>Current authenticated subject <strong>(User ID: ${escapeHtml(String(currentId))})</strong> does not possess the <code>admin</code> role or <code>audit:read</code> permission required to inspect the forensic audit trail.</p>
                            <p>To grant access, execute the following command in your terminal and reload:</p>
                            <div class="d-flex align-items-center gap-2">
                                <code class="breakable-mono p-2">${escapeHtml(promoCmd)}</code>
                                <button class="btn btn-sm btn-secondary" id="btn-copy-audit-promo">Copy Command</button>
                            </div>
                        </div>
                    `;
                    diagBox.style.display = 'block';

                    document.getElementById('btn-copy-audit-promo')?.addEventListener('click', () => {
                        copyToClipboard(promoCmd).then(() => {
                            showToast('Promotion command copied to clipboard!', 'success', 2000);
                        });
                    });
                }

                tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger">403 Forbidden: Insufficient Casbin permissions. See diagnostic above.</td></tr>`;
                return;
            }

            if (res.ok && res.data) {
                const items = Array.isArray(res.data) ? res.data : (res.data.items || []);
                this.currentLogs = items;

                if (items.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No audit events matched current criteria.</td></tr>';
                    return;
                }

                tbody.innerHTML = items.map(log => {
                    const isSuccess = log.outcome === 'SUCCESS' || log.status === 'SUCCESS' || (log.status_code >= 200 && log.status_code < 400);
                    const sev = log.severity || 'INFO';
                    let sevBadge = 'badge-info';
                    if (sev === 'WARNING') sevBadge = 'badge-warning';
                    if (sev === 'ERROR' || sev === 'CRITICAL') sevBadge = 'badge-danger';

                    return `
                        <tr class="audit-row" data-id="${log.id}">
                            <td class="font-mono text-xs">${formatDate(log.timestamp || log.created_at)}</td>
                            <td><span class="bold">${escapeHtml(log.event_type || log.action || '-')}</span></td>
                            <td><span class="badge ${sevBadge}">${escapeHtml(sev)}</span></td>
                            <td>${renderBadge(isSuccess ? 'success' : 'danger', log.outcome || log.status || (isSuccess ? 'SUCCESS' : 'FAILURE'))}</td>
                            <td><span class="breakable-mono">${escapeHtml(String(log.actor_id || log.user_id || 'System'))}</span></td>
                            <td>
                                <button class="btn btn-xs btn-outline btn-inspect-audit" data-id="${log.id}">View Diff</button>
                            </td>
                        </tr>
                    `;
                }).join('');

                // Attach click listeners
                tbody.querySelectorAll('.btn-inspect-audit').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        const id = btn.dataset.id;
                        this.inspectLog(id);
                    });
                });

                tbody.querySelectorAll('.audit-row').forEach(row => {
                    row.addEventListener('click', () => {
                        const id = row.dataset.id;
                        this.inspectLog(id);
                    });
                });

                // Update pagination controls
                const pageInd = document.getElementById('audit-page-indicator');
                const prevBtn = document.getElementById('btn-audit-prev');
                const nextBtn = document.getElementById('btn-audit-next');
                if (pageInd) pageInd.textContent = `Page ${this.page}`;
                if (prevBtn) prevBtn.disabled = this.page <= 1;
                if (nextBtn) nextBtn.disabled = items.length < this.pageSize;

            } else {
                tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Failed to load logs (Status ${res.status})</td></tr>`;
            }
        } catch (err) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Error: ${escapeHtml(err.message)}</td></tr>`;
        }
    }

    inspectLog(logId) {
        const log = this.currentLogs.find(l => String(l.id) === String(logId));
        if (!log) return;
        this.selectedLog = log;

        const panel = document.getElementById('audit-detail-panel');
        if (!panel) return;

        const isSuccess = log.outcome === 'SUCCESS' || log.status === 'SUCCESS';
        panel.innerHTML = `
            <div class="card-header p-0 mb-3">
                <h4>Audit Log #${log.id} — ${escapeHtml(log.event_type || log.action || 'Event')}</h4>
                ${renderBadge(isSuccess ? 'success' : 'danger', log.outcome || (isSuccess ? 'SUCCESS' : 'FAILURE'))}
            </div>

            <div class="claims-grid mb-3">
                <div class="claim-row">
                    <span class="claim-label">Timestamp (UTC):</span>
                    <span class="claim-val font-mono">${escapeHtml(String(log.timestamp || log.created_at || '-'))}</span>
                </div>
                <div class="claim-row">
                    <span class="claim-label">Actor ID / Target Entity:</span>
                    <span class="claim-val breakable-mono">${escapeHtml(String(log.actor_id || log.user_id || 'System'))} ➔ ${escapeHtml(String(log.entity_type || '-'))} (ID: ${escapeHtml(String(log.entity_id || '-'))})</span>
                </div>
                <div class="claim-row">
                    <span class="claim-label">Correlation X-Request-ID:</span>
                    <span class="claim-val breakable-mono">${escapeHtml(log.request_id || 'None')}</span>
                </div>
                <div class="claim-row">
                    <span class="claim-label">Client IP / User-Agent:</span>
                    <span class="claim-val breakable-mono">${escapeHtml(log.ip_address || '127.0.0.1')} | ${escapeHtml(log.user_agent || '-')}</span>
                </div>
            </div>

            <div class="card-section">
                <h4>Changes Payload (State Diff):</h4>
                <pre class="code-block">${syntaxHighlightJson(log.changes_payload || log.changes || {})}</pre>
            </div>

            <div class="card-section mt-3">
                <h4>Extra Metadata:</h4>
                <pre class="code-block">${syntaxHighlightJson(log.extra_data || log.metadata || {})}</pre>
            </div>
        `;
    }

    async handleExport(format) {
        showToast(`Preparing ${format.toUpperCase()} export...`, 'info', 1500);
        const res = await exportAuditLogs(format);

        if (res.ok && res.data) {
            const previewBox = document.getElementById('export-preview-box');
            const previewTitle = document.getElementById('export-preview-title');
            const previewContent = document.getElementById('export-preview-content');
            const downloadBtn = document.getElementById('btn-download-export');

            if (previewBox && previewContent) {
                previewBox.style.display = 'block';
                if (previewTitle) previewTitle.textContent = `Export Preview (${format.toUpperCase()})`;
                const textContent = typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2);
                previewContent.textContent = textContent;

                if (downloadBtn) {
                    downloadBtn.onclick = () => {
                        const blob = new Blob([textContent], { type: format === 'json' ? 'application/json' : 'text/plain' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `audit_export_${Date.now()}.${format === 'markdown' ? 'md' : format}`;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                        showToast(`✓ Downloaded ${format.toUpperCase()} export!`, 'success');
                    };
                }
            }
        } else {
            showToast(`Export failed: Status ${res.status}`, 'error');
        }
    }
}
