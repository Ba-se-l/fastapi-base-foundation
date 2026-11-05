/**
 * Network Inspector Panel
 * Captures all HTTP transactions from HttpClient, provides split-pane inspection,
 * cURL generator, and latency/request-id telemetry.
 */
import { eventBus } from '../core/event-emitter.js';
import { syntaxHighlightJson, copyToClipboard, showToast, escapeHtml } from './ui-helpers.js';

class NetworkInspector {
    constructor() {
        this.transactions = [];
        this.activeTransaction = null;
        this.filter = 'all'; // 'all', '2xx', '4xx', '5xx'
        this.isDrawerExpanded = false;
        this._initListeners();
    }

    _initListeners() {
        eventBus.on('http:transaction', (tx) => {
            this.addTransaction(tx);
        });
    }

    bindDOM() {
        this.toggleBtn = document.getElementById('inspector-toggle-btn');
        this.closeBtn = document.getElementById('inspector-close-btn');
        this.drawer = document.getElementById('network-inspector-drawer');
        this.counterBadge = document.getElementById('inspector-count-badge');
        this.titleBadge = document.getElementById('inspector-title-badge');
        this.listEl = document.getElementById('inspector-tx-list');
        this.detailEl = document.getElementById('inspector-tx-detail');
        this.clearBtn = document.getElementById('inspector-clear-btn');
        this.filterBtns = document.querySelectorAll('.inspector-filter-btn');

        if (this.toggleBtn && this.drawer) {
            this.toggleBtn.addEventListener('click', () => this.toggleDrawer());
        }

        if (this.closeBtn && this.drawer) {
            this.closeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.toggleDrawer();
            });
        }

        const header = document.getElementById('inspector-drawer-header');
        if (header) {
            header.addEventListener('click', (e) => {
                if (e.target.closest('button')) return;
                this.toggleDrawer();
            });
        }

        if (this.clearBtn) {
            this.clearBtn.addEventListener('click', () => this.clear());
        }

        if (this.filterBtns) {
            this.filterBtns.forEach(btn => {
                btn.addEventListener('click', () => {
                    this.filterBtns.forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    this.filter = btn.dataset.filter || 'all';
                    this.renderList();
                });
            });
        }
    }

    toggleDrawer(forceState = null) {
        if (!this.drawer) return;
        const isCurrentlyCollapsed = this.drawer.classList.contains('collapsed');
        const shouldCollapse = forceState !== null ? !forceState : !isCurrentlyCollapsed;

        if (shouldCollapse) {
            this.drawer.classList.add('collapsed');
            if (this.closeBtn) this.closeBtn.textContent = '▲ Expand';
        } else {
            this.drawer.classList.remove('collapsed');
            if (this.closeBtn) this.closeBtn.textContent = '▼ Collapse';
        }
    }

    addTransaction(tx) {
        const item = {
            id: 'tx_' + Math.random().toString(36).substring(2, 9),
            ...tx,
        };
        this.transactions.unshift(item);
        if (this.transactions.length > 50) {
            this.transactions.pop();
        }

        this.activeTransaction = item;
        this.updateBadge();
        this.renderList();
        this.renderDetail();
    }

    clear() {
        this.transactions = [];
        this.activeTransaction = null;
        this.updateBadge();
        this.renderList();
        this.renderDetail();
        showToast('Inspector network log cleared', 'info', 2000);
    }

    updateBadge() {
        const count = this.transactions.length;
        if (this.counterBadge) this.counterBadge.textContent = count;
        if (this.titleBadge) this.titleBadge.textContent = `${count} request${count === 1 ? '' : 's'}`;
    }

    renderList() {
        if (!this.listEl) return;
        
        let filtered = this.transactions;
        if (this.filter === '2xx') {
            filtered = this.transactions.filter(t => t.response.status >= 200 && t.response.status < 300);
        } else if (this.filter === '4xx') {
            filtered = this.transactions.filter(t => t.response.status >= 400 && t.response.status < 500);
        } else if (this.filter === '5xx') {
            filtered = this.transactions.filter(t => t.response.status >= 500 || t.response.status === 0);
        }

        if (filtered.length === 0) {
            this.listEl.innerHTML = '<div class="empty-state-small">No network transactions yet</div>';
            return;
        }

        this.listEl.innerHTML = filtered.map(t => {
            const isSelected = this.activeTransaction?.id === t.id ? 'active' : '';
            const status = t.response.status;
            let statusBadge = 'badge-200';
            if (status >= 400 && status < 500) statusBadge = 'badge-401';
            else if (status >= 500 || status === 0) statusBadge = 'badge-500';

            let urlDisplay = t.request.url;
            try {
                const parsed = new URL(t.request.url, window.location.origin);
                urlDisplay = parsed.pathname + parsed.search;
            } catch {}

            return `
                <div class="card p-2 mb-2 ${isSelected}" data-id="${t.id}" style="cursor: pointer; ${isSelected ? 'border-color: var(--primary); background-color: var(--primary-subtle);' : ''}">
                    <div class="d-flex justify-content-between align-items-center mb-1">
                        <span class="badge badge-info">${escapeHtml(t.request.method)}</span>
                        <span class="badge ${statusBadge}">${status || 'ERR'}</span>
                        <span class="font-mono text-xs text-muted">${t.response.durationMs}ms</span>
                    </div>
                    <div class="font-mono text-xs breakable-mono" title="${escapeHtml(t.request.url)}">${escapeHtml(urlDisplay)}</div>
                    <div class="d-flex justify-content-between text-muted mt-1" style="font-size: 0.72rem;">
                        <span>${t.request.deviceSlot === 'device_b' ? 'Device B' : 'Device A'}</span>
                        <span>${new Date(t.request.timestamp).toLocaleTimeString()}</span>
                    </div>
                </div>
            `;
        }).join('');

        this.listEl.querySelectorAll('.card[data-id]').forEach(el => {
            el.addEventListener('click', () => {
                const id = el.dataset.id;
                this.activeTransaction = this.transactions.find(t => t.id === id);
                this.renderList();
                this.renderDetail();
            });
        });
    }

    renderDetail() {
        if (!this.detailEl) return;
        const tx = this.activeTransaction;
        if (!tx) {
            this.detailEl.innerHTML = '<div class="empty-state">Select a request on the left to inspect headers, payload, and envelopes.</div>';
            return;
        }

        const req = tx.request;
        const res = tx.response;
        const reqId = res.headers?.['x-request-id'] || req.headers?.['x-request-id'] || req.headers?.['X-Request-ID'] || 'None';

        this.detailEl.innerHTML = `
            <div class="card p-3">
                <div class="d-flex justify-content-between align-items-center mb-2 flex-wrap gap-2">
                    <div class="d-flex align-items-center gap-2">
                        <span class="badge badge-info">${escapeHtml(req.method)}</span>
                        <span class="font-mono text-xs breakable-mono" title="${escapeHtml(req.url)}">${escapeHtml(req.url)}</span>
                    </div>
                    <div class="d-flex gap-2">
                        <button class="btn btn-xs btn-outline" id="btn-copy-curl">Copy cURL</button>
                        <button class="btn btn-xs btn-outline" id="btn-copy-json">Copy JSON</button>
                    </div>
                </div>

                <div class="claims-grid mb-3">
                    <div class="claim-row">
                        <span class="claim-label">Status & Duration:</span>
                        <span class="claim-val bold">${res.status} ${escapeHtml(res.statusText || '')} (${res.durationMs} ms)</span>
                    </div>
                    <div class="claim-row">
                        <span class="claim-label">Device Slot / Request ID:</span>
                        <span class="claim-val breakable-mono">${req.deviceSlot} | ${escapeHtml(reqId)}</span>
                    </div>
                </div>

                <div class="btn-group mb-2">
                    <button class="btn btn-xs btn-outline detail-tab-btn active" data-tab="res-body">Response Body</button>
                    <button class="btn btn-xs btn-outline detail-tab-btn" data-tab="req-body">Request Body</button>
                    <button class="btn btn-xs btn-outline detail-tab-btn" data-tab="res-headers">Response Headers</button>
                    <button class="btn btn-xs btn-outline detail-tab-btn" data-tab="req-headers">Request Headers</button>
                </div>

                <div class="detail-tab-contents">
                    <div class="detail-pane active" id="pane-res-body">
                        <pre class="code-block">${syntaxHighlightJson(res.data)}</pre>
                    </div>
                    <div class="detail-pane" id="pane-req-body" style="display: none;">
                        <pre class="code-block">${req.body ? syntaxHighlightJson(req.body) : '<span class="text-muted">&lt;No Request Body&gt;</span>'}</pre>
                    </div>
                    <div class="detail-pane" id="pane-res-headers" style="display: none;">
                        <table class="data-table">
                            <thead><tr><th>Header</th><th>Value</th></tr></thead>
                            <tbody>
                                ${Object.entries(res.headers || {}).map(([k, v]) => `<tr><td class="bold font-mono text-xs">${escapeHtml(k)}</td><td class="breakable-mono">${escapeHtml(v)}</td></tr>`).join('')}
                            </tbody>
                        </table>
                    </div>
                    <div class="detail-pane" id="pane-req-headers" style="display: none;">
                        <table class="data-table">
                            <thead><tr><th>Header</th><th>Value</th></tr></thead>
                            <tbody>
                                ${Object.entries(req.headers || {}).map(([k, v]) => `<tr><td class="bold font-mono text-xs">${escapeHtml(k)}</td><td class="breakable-mono">${escapeHtml(v)}</td></tr>`).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;

        const tabBtns = this.detailEl.querySelectorAll('.detail-tab-btn');
        const panes = this.detailEl.querySelectorAll('.detail-pane');
        tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                tabBtns.forEach(b => b.classList.remove('active'));
                panes.forEach(p => { p.style.display = 'none'; p.classList.remove('active'); });
                btn.classList.add('active');
                const target = this.detailEl.querySelector(`#pane-${btn.dataset.tab}`);
                if (target) {
                    target.style.display = 'block';
                    target.classList.add('active');
                }
            });
        });

        const copyCurlBtn = this.detailEl.querySelector('#btn-copy-curl');
        if (copyCurlBtn) {
            copyCurlBtn.addEventListener('click', () => {
                const curlCmd = this.generateCurl(tx);
                copyToClipboard(curlCmd).then(() => {
                    showToast('cURL command copied to clipboard!', 'success', 2000);
                });
            });
        }

        const copyJsonBtn = this.detailEl.querySelector('#btn-copy-json');
        if (copyJsonBtn) {
            copyJsonBtn.addEventListener('click', () => {
                const jsonStr = JSON.stringify(res.data, null, 2);
                copyToClipboard(jsonStr).then(() => {
                    showToast('Response JSON copied to clipboard!', 'success', 2000);
                });
            });
        }
    }

    generateCurl(tx) {
        const req = tx.request;
        let cmd = `curl -X ${req.method} "${req.url}"`;
        for (const [k, v] of Object.entries(req.headers || {})) {
            cmd += ` \\\n  -H "${k}: ${v.replace(/"/g, '\\"')}"`;
        }
        if (req.body) {
            const bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
            cmd += ` \\\n  --data '${bodyStr.replace(/'/g, "'\\''")}'`;
        }
        return cmd;
    }
}

export const networkInspector = new NetworkInspector();
