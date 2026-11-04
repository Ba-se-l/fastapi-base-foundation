/**
 * Multi-Device Session Store (SEC-08 Hardened)
 * Uses sessionStorage (tab-isolated, cleared on window close) instead of permanent localStorage.
 * Manages concurrent virtual devices (Device A vs Device B) and Replay Test Buffer.
 */
import { decodeJwt } from './jwt-decoder.js';
import { eventBus } from './event-emitter.js';

const STORAGE_KEY = 'fastapi_workbench_sessions_v1';

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
                if (raw) return JSON.parse(raw);
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
            replayBuffer: null, // { token, deviceSlot, rotatedAt, previousFid, previousJti }
            customRequestId: '',
        };
    }

    _save() {
        const storage = this._getStorage();
        if (storage) {
            try {
                storage.setItem(STORAGE_KEY, JSON.stringify(this.state));
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
        if (slot === 'device_a' || slot === 'device_b') {
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
        this.state[targetSlot] = null;
        this._save();
    }

    clearAllSessions() {
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
        this.state.replayBuffer = null;
        this._save();
    }

    // Custom Request ID override
    getCustomRequestId() {
        return this.state.customRequestId || '';
    }

    setCustomRequestId(val) {
        this.state.customRequestId = val.trim();
        this._save();
    }
}

export const sessionStore = new SessionStore();
