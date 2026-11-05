/**
 * Multi-Device Session Store (SEC-08 & SEC-32 Hardened)
 * Retains raw cryptographic JWT credentials inside an isolated in-memory ES module closure vault
 * (_tokenMemoryVault), writing only redacted metadata markers to sessionStorage.
 * Prevents credential harvesting via Web Storage inspection while supporting tab persistence.
 */
import { decodeJwt } from './jwt-decoder.js';
import { eventBus } from './event-emitter.js';

const STORAGE_KEY = 'fastapi_workbench_sessions_v1';
const VAULT_MARKER = '[VAULT_IN_MEMORY]';

// Module-scoped in-memory vault inaccessible to external scripts/DOM inspection
const _tokenMemoryVault = new Map();

class SessionStore {
    constructor() {
        this.memoryFallback = null;
        this.state = this._load();
    }

    _getStorage() {
        try {
            if (typeof window !== 'undefined' && window.sessionStorage) {
                return window.sessionStorage;
            }
        } catch (e) {
            console.warn('sessionStorage unavailable, falling back to memory:', e);
        }
        return null;
    }

    _load() {
        const storage = this._getStorage();
        try {
            if (storage) {
                const raw = storage.getItem(STORAGE_KEY);
                if (raw) {
                    const parsed = JSON.parse(raw);
                    // Re-link tokens from memory vault if available
                    for (const slot of ['device_a', 'device_b']) {
                        if (parsed[slot] && _tokenMemoryVault.has(slot)) {
                            const vaultData = _tokenMemoryVault.get(slot);
                            parsed[slot].accessToken = vaultData.accessToken;
                            parsed[slot].refreshToken = vaultData.refreshToken;
                        }
                    }
                    if (parsed.replayBuffer && _tokenMemoryVault.has('replayBuffer')) {
                        parsed.replayBuffer.token = _tokenMemoryVault.get('replayBuffer');
                    }
                    return parsed;
                }
            } else if (this.memoryFallback) {
                return this.memoryFallback;
            }
        } catch (e) {
            console.error('Failed to parse session storage:', e);
        }
        return {
            activeSlot: 'device_a',
            device_a: null,
            device_b: null,
            replayBuffer: null,
            customRequestId: '',
        };
    }

    _getSanitizedState() {
        const copy = JSON.parse(JSON.stringify(this.state));
        for (const slot of ['device_a', 'device_b']) {
            if (copy[slot]) {
                copy[slot].accessToken = copy[slot].accessToken ? VAULT_MARKER : null;
                copy[slot].refreshToken = copy[slot].refreshToken ? VAULT_MARKER : null;
            }
        }
        if (copy.replayBuffer && copy.replayBuffer.token) {
            copy.replayBuffer.token = VAULT_MARKER;
        }
        return copy;
    }

    _save() {
        const storage = this._getStorage();
        if (storage) {
            try {
                storage.setItem(STORAGE_KEY, JSON.stringify(this._getSanitizedState()));
            } catch (e) {
                console.error('Failed to write to sessionStorage:', e);
            }
        } else {
            this.memoryFallback = JSON.parse(JSON.stringify(this.state));
        }
        eventBus.emit('session:changed', this.state);
    }

    getActiveSlot() {
        return this.state.activeSlot || 'device_a';
    }

    setActiveSlot(slot) {
        if ((slot === 'device_a' || slot === 'device_b') && this.state.activeSlot !== slot) {
            this.state.activeSlot = slot;
            this._save();
        }
    }

    getSession(slot = null) {
        const targetSlot = slot || this.getActiveSlot();
        return this.state[targetSlot] || null;
    }

    setSession(slot, { accessToken, refreshToken = null, user = null }) {
        const decodedAccess = accessToken ? decodeJwt(accessToken) : null;
        const decodedRefresh = refreshToken ? decodeJwt(refreshToken) : null;

        // Store raw tokens in module-level RAM vault
        _tokenMemoryVault.set(slot, {
            accessToken: accessToken || null,
            refreshToken: refreshToken || null,
        });

        this.state[slot] = {
            accessToken,
            refreshToken: refreshToken || null,
            user,
            accessClaims: decodedAccess,
            refreshClaims: decodedRefresh,
            updatedAt: new Date().toISOString(),
        };
        this._save();
    }

    clearSession(slot = null) {
        const targetSlot = slot || this.getActiveSlot();
        _tokenMemoryVault.delete(targetSlot);
        this.state[targetSlot] = null;
        this._save();
    }

    removeSession(slot = null) {
        return this.clearSession(slot);
    }

    clearAllSessions() {
        _tokenMemoryVault.delete('device_a');
        _tokenMemoryVault.delete('device_b');
        _tokenMemoryVault.delete('replayBuffer');
        this.state.device_a = null;
        this.state.device_b = null;
        this.state.replayBuffer = null;
        this._save();
    }

    purgeAllSessions() {
        const storage = this._getStorage();
        if (storage) {
            try {
                storage.removeItem(STORAGE_KEY);
            } catch (e) {}
        }
        _tokenMemoryVault.clear();
        this.memoryFallback = null;
        this.state = {
            activeSlot: 'device_a',
            device_a: null,
            device_b: null,
            replayBuffer: null,
            customRequestId: '',
        };
        this._save();
    }

    // Replay Attack Test Buffer
    setReplayBuffer(data) {
        if (data && data.token) {
            _tokenMemoryVault.set('replayBuffer', data.token);
        }
        this.state.replayBuffer = {
            ...data,
            capturedAt: new Date().toISOString(),
        };
        this._save();
    }

    getReplayBuffer() {
        return this.state.replayBuffer;
    }

    clearReplayBuffer() {
        _tokenMemoryVault.delete('replayBuffer');
        this.state.replayBuffer = null;
        this._save();
    }

    // Custom Request ID override
    getCustomRequestId() {
        return this.state.customRequestId || '';
    }

    setCustomRequestId(val) {
        const trimmed = (val || '').trim();
        if (this.state.customRequestId !== trimmed) {
            this.state.customRequestId = trimmed;
            this._save();
        }
    }
}

export const sessionStore = new SessionStore();
