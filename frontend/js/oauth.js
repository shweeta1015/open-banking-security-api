/**
 * OAuth 2.0 PKCE & Token Utilities for OpenBankingSecurityAPI
 */

class OAuthManager {
    /**
     * Generate RFC 7636 compliant PKCE code_verifier (43-128 chars)
     */
    static generateCodeVerifier() {
        const array = new Uint8Array(32);
        window.crypto.getRandomValues(array);
        return OAuthManager.base64UrlEncode(array);
    }

    /**
     * Convert Uint8Array or String to URL-safe Base64 without padding
     */
    static base64UrlEncode(bytes) {
        let binary = '';
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    /**
     * Compute SHA-256 code_challenge from code_verifier
     */
    static async generateCodeChallenge(verifier) {
        const encoder = new TextEncoder();
        const data = encoder.encode(verifier);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
        return OAuthManager.base64UrlEncode(new Uint8Array(hashBuffer));
    }

    /**
     * Generate random state for CSRF protection
     */
    static generateState() {
        const array = new Uint8Array(16);
        window.crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Parse JWT payload without external library
     */
    static decodeJwt(token) {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) return null;
            const payload = parts[1];
            const padded = payload + '='.repeat((4 - payload.length % 4) % 4);
            const decoded = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
            return JSON.parse(decoded);
        } catch (e) {
            console.error("Failed to decode JWT:", e);
            return null;
        }
    }

    /**
     * Parse JWT header
     */
    static decodeJwtHeader(token) {
        try {
            const parts = token.split('.');
            if (parts.length < 1) return null;
            const header = parts[0];
            const padded = header + '='.repeat((4 - header.length % 4) % 4);
            const decoded = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
            return JSON.parse(decoded);
        } catch (e) {
            return null;
        }
    }
}
