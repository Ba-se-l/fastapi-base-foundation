/**
 * Authentication Module API
 * Interacts with /api/v1/auth endpoints
 */
import { httpClient } from '../../core/http-client.js';

export async function register(userData) {
    return await httpClient.post('/api/v1/auth/register', userData);
}

export async function login(credentials) {
    return await httpClient.post('/api/v1/auth/login', credentials);
}

export async function refreshToken(refreshToken) {
    return await httpClient.post('/api/v1/auth/refresh', {
        refresh_token: refreshToken
    });
}

export async function logout(refreshToken) {
    return await httpClient.post('/api/v1/auth/logout', {
        refresh_token: refreshToken
    });
}

export async function logoutAll() {
    return await httpClient.post('/api/v1/auth/logout-all', {});
}

export async function changePassword(passwords) {
    return await httpClient.post('/api/v1/auth/change-password', passwords);
}
