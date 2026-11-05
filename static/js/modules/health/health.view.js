/**
 * Health & Telemetry View
 * Monitors server status, database readiness, response latency, and environment.
 */
import { checkHealth, checkHealthReady } from './health.api.js';
import { showToast, escapeHtml, syntaxHighlightJson } from '../../shared/ui-helpers.js';

export class HealthView {
    constructor() {
        this.pollInterval = null;
        this.isAutoPolling = false;
    }

    render() {
        return `
            <div class="module-card">
                <div class="card-header">
                    <div class="header-title">
                        <h2>Infrastructure Health & Telemetry</h2>
                        <span class="subtitle">Real-time status of backend services, database connectivity, and telemetry</span>
                    </div>
                    <div class="header-actions">
                        <button class="btn btn-secondary" id="btn-health-poll-toggle">
                            <span class="status-dot" id="poll-indicator"></span> Auto-Poll (5s): <strong id="poll-status-text">OFF</strong>
                        </button>
                        <button class="btn btn-primary" id="btn-health-refresh">
                            <span>↻</span> Ping Health Now
                        </button>
                    </div>
                </div>

                <div class="health-metrics-grid" id="health-metrics-grid">
                    <div class="metric-card">
                        <div class="metric-icon" id="metric-status-icon">⏳</div>
                        <div class="metric-content">
                            <span class="metric-label">System Liveness (/health)</span>
                            <span class="metric-val" id="metric-status-val">Checking...</span>
                        </div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-icon">🗄️</div>
                        <div class="metric-content">
                            <span class="metric-label">DB Readiness (/health/ready)</span>
                            <span class="metric-val" id="metric-db-val">-</span>
                        </div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-icon">⚡</div>
                        <div class="metric-content">
                            <span class="metric-label">Response Latency</span>
                            <span class="metric-val" id="metric-latency-val">-</span>
                        </div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-icon">🏷️</div>
                        <div class="metric-content">
                            <span class="metric-label">App Environment</span>
                            <span class="metric-val" id="metric-env-val">-</span>
                        </div>
                    </div>
                </div>

                <div class="card-section mt-4">
                    <h3>Raw Telemetry Payloads</h3>
                    <div class="grid-2">
                        <div class="card">
                            <h4>GET /health</h4>
                            <pre class="code-block" id="health-raw-preview">Loading...</pre>
                        </div>
                        <div class="card">
                            <h4>GET /health/ready</h4>
                            <pre class="code-block" id="ready-raw-preview">Loading...</pre>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    bindEvents() {
        const refreshBtn = document.getElementById('btn-health-refresh');
        const pollBtn = document.getElementById('btn-health-poll-toggle');

        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.fetchStatus(true));
        }

        if (pollBtn) {
            pollBtn.addEventListener('click', () => this.togglePolling());
        }

        this.fetchStatus(false);
    }

    cleanup() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
        this.isAutoPolling = false;
    }

    togglePolling() {
        this.isAutoPolling = !this.isAutoPolling;
        const statusText = document.getElementById('poll-status-text');
        const dot = document.getElementById('poll-indicator');

        if (this.isAutoPolling) {
            if (statusText) statusText.textContent = 'ON';
            if (dot) dot.classList.add('online');
            this.pollInterval = setInterval(() => this.fetchStatus(false), 5000);
            showToast('Auto-polling activated (5s interval)', 'info', 1500);
        } else {
            if (statusText) statusText.textContent = 'OFF';
            if (dot) dot.classList.remove('online');
            if (this.pollInterval) {
                clearInterval(this.pollInterval);
                this.pollInterval = null;
            }
            showToast('Auto-polling paused', 'info', 1500);
        }
    }

    async fetchStatus(manual = false) {
        const statusVal = document.getElementById('metric-status-val');
        const dbVal = document.getElementById('metric-db-val');
        const latencyVal = document.getElementById('metric-latency-val');
        const envVal = document.getElementById('metric-env-val');
        const rawHealth = document.getElementById('health-raw-preview');
        const rawReady = document.getElementById('ready-raw-preview');
        const icon = document.getElementById('metric-status-icon');

        const t0 = performance.now();
        try {
            const [healthRes, readyRes] = await Promise.all([
                checkHealth(),
                checkHealthReady(),
            ]);
            const latency = Math.round(performance.now() - t0);

            if (latencyVal) latencyVal.textContent = `${latency} ms`;

            if (healthRes.ok && healthRes.data) {
                if (statusVal) statusVal.innerHTML = `<span class="badge badge-success">● ${escapeHtml(healthRes.data.status || 'OK')}</span>`;
                if (envVal) envVal.textContent = healthRes.data.environment || 'DEV';
                if (rawHealth) rawHealth.innerHTML = syntaxHighlightJson(healthRes.data);
                if (icon) icon.textContent = '⚡';
            } else {
                if (statusVal) statusVal.innerHTML = `<span class="badge badge-danger">Offline (${healthRes.status})</span>`;
                if (rawHealth) rawHealth.textContent = `Status: ${healthRes.status}`;
            }

            if (readyRes.ok && readyRes.data) {
                const dbStatus = readyRes.data?.checks?.database || readyRes.data?.status || 'ok';
                if (dbVal) dbVal.innerHTML = `<span class="badge badge-success">✓ ${escapeHtml(dbStatus)}</span>`;
                if (rawReady) rawReady.innerHTML = syntaxHighlightJson(readyRes.data);
            } else {
                if (dbVal) dbVal.innerHTML = `<span class="badge badge-danger">Unavailable (${readyRes.status})</span>`;
                if (rawReady) rawReady.textContent = `Status: ${readyRes.status}`;
            }

            if (manual) showToast(`✓ Telemetry refreshed (${latency} ms)`, 'success', 1500);
        } catch (err) {
            if (statusVal) statusVal.innerHTML = `<span class="badge badge-danger">Error</span>`;
            if (dbVal) dbVal.textContent = 'Unreachable';
            if (rawHealth) rawHealth.textContent = err.message;
            if (rawReady) rawReady.textContent = err.message;
            if (icon) icon.textContent = '⚠️';
        }
    }
}
