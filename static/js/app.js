/**
 * Application Orchestrator & Bootloader
 * Coordinates routing, tabs, top bar telemetry, multi-device switcher, and modules.
 */
import { HealthView } from './modules/health/health.view.js';
import { AuthView } from './modules/auth/auth.view.js';
import { UserView } from './modules/user/user.view.js';
import { AuditView } from './modules/audit/audit.view.js';
import { SecurityLabView } from './modules/security-lab/lab.view.js';
import { networkInspector } from './shared/inspector-panel.js';
import { sessionStore } from './core/session-store.js';
import { eventBus } from './core/event-emitter.js';
import { checkHealth } from './modules/health/health.api.js';

class App {
    constructor() {
        this.views = {
            'health': new HealthView(),
            'auth': new AuthView(),
            'user': new UserView(),
            'audit': new AuditView(),
            'security-lab': new SecurityLabView(),
        };
        this.currentTab = 'health';
        this.currentViewInstance = null;
    }

    init() {
        this.bindNavigation();
        this.bindTopBar();
        networkInspector.bindDOM();
        this.bindSessionSync();

        // Listen for URL hash routing or default to health
        const initialTab = window.location.hash.replace('#', '') || 'health';
        this.switchTab(initialTab in this.views ? initialTab : 'health');

        // Ping health for top-bar status indicator
        this.pingHealthStatus();
        setInterval(() => this.pingHealthStatus(), 30000);
    }

    bindNavigation() {
        document.querySelectorAll('.sidebar .nav-item[data-tab], .app-sidebar .nav-item[data-tab]').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const tab = item.dataset.tab;
                this.switchTab(tab);
            });
        });

        window.addEventListener('hashchange', () => {
            const tab = window.location.hash.replace('#', '');
            if (tab && tab in this.views && tab !== this.currentTab) {
                this.switchTab(tab);
            }
        });
    }

    switchTab(tabName) {
        if (!this.views[tabName]) return;

        // Cleanup current view if method exists
        if (this.currentViewInstance && typeof this.currentViewInstance.cleanup === 'function') {
            this.currentViewInstance.cleanup();
        }

        this.currentTab = tabName;
        window.location.hash = `#${tabName}`;

        // Update sidebar active classes
        document.querySelectorAll('.sidebar .nav-item[data-tab], .app-sidebar .nav-item[data-tab]').forEach(el => {
            if (el.dataset.tab === tabName) {
                el.classList.add('active');
            } else {
                el.classList.remove('active');
            }
        });

        // Mount new view
        const viewport = document.getElementById('workspace-viewport');
        if (viewport) {
            this.currentViewInstance = this.views[tabName];
            viewport.innerHTML = this.currentViewInstance.render();
            if (typeof this.currentViewInstance.bindEvents === 'function') {
                this.currentViewInstance.bindEvents();
            }
        }
    }

    bindTopBar() {
        const topDevA = document.getElementById('top-device-a');
        const topDevB = document.getElementById('top-device-b');
        const inputReqId = document.getElementById('input-custom-request-id');

        // Device Slot switchers
        if (topDevA) {
            topDevA.addEventListener('click', () => {
                sessionStore.setActiveSlot('device_a');
            });
        }
        if (topDevB) {
            topDevB.addEventListener('click', () => {
                sessionStore.setActiveSlot('device_b');
            });
        }

        // Custom Request ID override
        if (inputReqId) {
            inputReqId.value = sessionStore.getCustomRequestId();
            inputReqId.addEventListener('input', (e) => {
                sessionStore.setCustomRequestId(e.target.value);
            });
        }

        this.updateTopBarState();
    }

    bindSessionSync() {
        eventBus.on('session:changed', () => {
            this.updateTopBarState();
        });
    }

    updateTopBarState() {
        const activeSlot = sessionStore.getActiveSlot();
        const session = sessionStore.getSession(activeSlot);

        // Update top device pills
        const topDevA = document.getElementById('top-device-a');
        const topDevB = document.getElementById('top-device-b');
        if (topDevA) {
            topDevA.classList.toggle('active', activeSlot === 'device_a');
        }
        if (topDevB) {
            topDevB.classList.toggle('active', activeSlot === 'device_b');
        }

        // Update user session chip
        const userChip = document.getElementById('top-user-label');
        if (userChip) {
            if (session?.accessToken) {
                const sub = session.accessClaims?.sub || 'User';
                const email = session.user?.email || (session.accessClaims?.email) || sub.substring(0, 12);
                userChip.innerHTML = `<strong>${activeSlot === 'device_b' ? 'Dev B' : 'Dev A'}:</strong> ${email}`;
            } else {
                userChip.innerHTML = `<strong>${activeSlot === 'device_b' ? 'Dev B' : 'Dev A'}:</strong> <span class="text-muted">Logged Out</span>`;
            }
        }
    }

    async pingHealthStatus() {
        const dot = document.getElementById('top-health-dot');
        const text = document.getElementById('top-health-text');
        try {
            const res = await checkHealth();
            if (res.ok && res.data) {
                if (dot) {
                    dot.className = 'status-dot online';
                }
                if (text) {
                    text.textContent = 'FastAPI Engine: Online';
                }
            } else {
                if (dot) dot.className = 'status-dot';
                if (text) text.textContent = 'FastAPI Engine: Degraded';
            }
        } catch {
            if (dot) dot.className = 'status-dot';
            if (text) text.textContent = 'FastAPI Engine: Offline';
        }
    }
}

// Boot application
const app = new App();
document.addEventListener('DOMContentLoaded', () => {
    app.init();
});
