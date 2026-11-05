/**
 * Audit Module API Client
 * Strips empty parameter strings to prevent 422 validation errors.
 */
import { httpClient } from '../../core/http-client.js';

export async function listAuditLogs(params = {}) {
    const cleanParams = {};
    for (const [k, v] of Object.entries(params)) {
        if (v !== '' && v !== null && v !== undefined) {
            cleanParams[k] = v;
        }
    }
    const qs = new URLSearchParams(cleanParams).toString();
    return await httpClient.get(`/api/v1/audit/logs${qs ? '?' + qs : ''}`);
}

export async function getAuditLog(logId) {
    return await httpClient.get(`/api/v1/audit/logs/${logId}`);
}

export async function exportAuditLogs(format = 'json', params = {}) {
    const cleanParams = {};
    for (const [k, v] of Object.entries(params)) {
        if (v !== '' && v !== null && v !== undefined) {
            cleanParams[k] = v;
        }
    }
    cleanParams.format = format;
    const qs = new URLSearchParams(cleanParams).toString();
    return await httpClient.get(`/api/v1/audit/export?${qs}`, { isBlob: false });
}
