/**
 * Unified HTTP Client with Live Network Inspector Logging (SEC-09 Redaction Hardened)
 * Injects Bearer tokens from active virtual device and custom X-Request-ID.
 * Deeply redacts sensitive credentials in inspector snapshots.
 */
import { sessionStore } from './session-store.js';
import { eventBus } from './event-emitter.js';

export function redactSensitiveHeaders(headersObj) {
    if (!headersObj || typeof headersObj !== 'object') return headersObj;
    const clean = {};
    for (const [k, v] of Object.entries(headersObj)) {
        if (/^(authorization|cookie|set-cookie)$/i.test(k)) {
            if (/^authorization$/i.test(k) && typeof v === 'string' && v.startsWith('Bearer ')) {
                clean[k] = 'Bearer [REDACTED]';
            } else {
                clean[k] = '[REDACTED]';
            }
        } else {
            clean[k] = v;
        }
    }
    return clean;
}

export function redactSensitivePayload(data) {
    if (!data) return data;
    if (typeof data === 'string') {
        try {
            const parsed = JSON.parse(data);
            return JSON.stringify(redactSensitivePayload(parsed));
        } catch {
            return data;
        }
    }
    if (Array.isArray(data)) {
        return data.map(item => redactSensitivePayload(item));
    }
    if (typeof data === 'object') {
        const clean = {};
        for (const [k, v] of Object.entries(data)) {
            if (/^(password|old_password|new_password|confirm_password|refresh_token|access_token|secret)$/i.test(k)) {
                clean[k] = '[REDACTED]';
            } else if (typeof v === 'object' && v !== null) {
                clean[k] = redactSensitivePayload(v);
            } else {
                clean[k] = v;
            }
        }
        return clean;
    }
    return data;
}

class HttpClient {
    async request(url, options = {}) {
        const activeSlot = sessionStore.getActiveSlot();
        const session = sessionStore.getSession(activeSlot);
        
        // Prepare Headers
        const headers = new Headers(options.headers || {});
        
        // 1. Authorization injection
        if (!headers.has('Authorization') && session?.accessToken) {
            headers.set('Authorization', `Bearer ${session.accessToken}`);
        }
        
        // 2. Correlation ID injection
        const customRequestId = sessionStore.getCustomRequestId();
        const requestId = customRequestId || (crypto.randomUUID ? crypto.randomUUID().replace(/-/g, '') : Math.random().toString(36).substring(2, 18));
        if (!headers.has('X-Request-ID')) {
            headers.set('X-Request-ID', requestId);
        }

        // 3. Content-Type default for JSON
        if (options.body && typeof options.body === 'string' && !headers.has('Content-Type')) {
            headers.set('Content-Type', 'application/json');
        }

        // Capture raw headers map for request
        const rawHeadersMap = Object.fromEntries(headers.entries());

        // Capture redacted request snapshot for Inspector
        const requestSnapshot = {
            method: (options.method || 'GET').toUpperCase(),
            url,
            headers: redactSensitiveHeaders(rawHeadersMap),
            body: redactSensitivePayload(options.body || null),
            timestamp: new Date().toISOString(),
            deviceSlot: activeSlot,
        };

        const startTime = performance.now();
        let response;
        let responseData = null;
        let isBlob = options.isBlob || false;
        let error = null;

        try {
            response = await fetch(url, {
                ...options,
                headers,
            });

            const durationMs = Math.round(performance.now() - startTime);
            const responseHeaders = Object.fromEntries(response.headers.entries());

            if (isBlob) {
                responseData = await response.blob();
            } else {
                const text = await response.text();
                try {
                    responseData = text ? JSON.parse(text) : null;
                } catch {
                    responseData = text;
                }
            }

            // Emit Redacted Snapshot to Network Inspector
            eventBus.emit('http:transaction', {
                request: requestSnapshot,
                response: {
                    status: response.status,
                    statusText: response.statusText,
                    headers: redactSensitiveHeaders(responseHeaders),
                    data: redactSensitivePayload(responseData),
                    durationMs,
                    ok: response.ok,
                }
            });

            return {
                ok: response.ok,
                status: response.status,
                data: responseData,
                headers: responseHeaders,
            };

        } catch (err) {
            const durationMs = Math.round(performance.now() - startTime);
            error = err.message || 'Network Error';

            eventBus.emit('http:transaction', {
                request: requestSnapshot,
                response: {
                    status: 0,
                    statusText: 'Network / Connection Failed',
                    headers: {},
                    data: { error },
                    durationMs,
                    ok: false,
                }
            });

            throw err;
        }
    }

    get(url, options = {}) {
        return this.request(url, { ...options, method: 'GET' });
    }

    post(url, body, options = {}) {
        return this.request(url, {
            ...options,
            method: 'POST',
            body: typeof body === 'object' ? JSON.stringify(body) : body,
        });
    }

    patch(url, body, options = {}) {
        return this.request(url, {
            ...options,
            method: 'PATCH',
            body: typeof body === 'object' ? JSON.stringify(body) : body,
        });
    }

    delete(url, options = {}) {
        return this.request(url, { ...options, method: 'DELETE' });
    }
}

export const httpClient = new HttpClient();
