/**
 * Client-Side Base64URL JWT Decoder
 * Extracts sub, fid (family_id), jti, sec_ver (security_version), type, exp.
 */
export function decodeJwt(token) {
    if (!token || typeof token !== 'string') return null;
    try {
        const parts = token.split('.');
        if (parts.length < 2) return null;
        
        // Base64URL to Base64 with padding
        const base64Url = parts[1];
        let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4 !== 0) {
            base64 += '=';
        }

        const jsonPayload = decodeURIComponent(
            atob(base64)
                .split('')
                .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                .join('')
        );
        return JSON.parse(jsonPayload);
    } catch (err) {
        console.warn('Failed to decode JWT:', err);
        return null;
    }
}

export function formatTimeRemaining(expTimestamp) {
    if (!expTimestamp) return 'No Expiry';
    const now = Math.floor(Date.now() / 1000);
    const diff = expTimestamp - now;
    if (diff <= 0) return 'Expired';
    
    const minutes = Math.floor(diff / 60);
    const seconds = diff % 60;
    if (minutes > 60) {
        const hours = Math.floor(minutes / 60);
        return `${hours}h ${minutes % 60}m`;
    }
    return `${minutes}m ${seconds}s`;
}
