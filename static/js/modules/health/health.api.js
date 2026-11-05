/**
 * Health Module API Client
 */
import { httpClient } from '../../core/http-client.js';

export async function checkHealth() {
    return await httpClient.get('/health');
}

export async function checkHealthReady() {
    return await httpClient.get('/health/ready');
}
