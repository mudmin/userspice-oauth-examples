import React, { useEffect, useState } from 'react';
import oauthConfig from './oauthConfig';
import './App.css';

/**
 * Generate a cryptographically secure random state parameter
 * Uses Web Crypto API for better security than Math.random()
 */
function generateSecureState() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Base64url encoding without padding (RFC 7636)
 */
function base64UrlEncode(bytes) {
    let binary = '';
    bytes.forEach(byte => {
        binary += String.fromCharCode(byte);
    });
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * PKCE code verifier: 32 random bytes, base64url encoded (43 characters)
 */
function generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64UrlEncode(array);
}

/**
 * PKCE S256 code challenge: base64url(SHA-256(verifier))
 */
async function generateCodeChallenge(verifier) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    return base64UrlEncode(new Uint8Array(digest));
}

function OAuthRequest() {
    const [redirecting, setRedirecting] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        async function startOAuthFlow() {
            try {
                if (!window.isSecureContext || !crypto.subtle) {
                    throw new Error('PKCE requires crypto.subtle, which is only available over https or on http://localhost.');
                }

                // Generate cryptographically secure state parameter for CSRF protection
                const state = generateSecureState();

                // Generate PKCE verifier and its S256 challenge
                const codeVerifier = generateCodeVerifier();
                const codeChallenge = await generateCodeChallenge(codeVerifier);

                // Store state and verifier for this tab only
                sessionStorage.setItem('oauth_state', state);
                sessionStorage.setItem('oauth_state_time', Date.now().toString());
                sessionStorage.setItem('oauth_code_verifier', codeVerifier);

                // Build authorization URL
                const authParams = new URLSearchParams({
                    response_type: 'code',
                    client_id: oauthConfig.clientId,
                    redirect_uri: oauthConfig.redirectUri,
                    state: state,
                    scope: oauthConfig.scope,
                    code_challenge: codeChallenge,
                    code_challenge_method: 'S256'
                });

                const authUrl = `${oauthConfig.serverUrl}users/auth/?${authParams}`;

                // Redirect to OAuth server
                window.location.href = authUrl;
            } catch (err) {
                setError('Failed to initiate OAuth flow: ' + err.message);
                setRedirecting(false);
            }
        }

        startOAuthFlow();
    }, []);

    if (error) {
        return (
            <div className="oauth-container">
                <div className="oauth-card error-card">
                    <h2>OAuth Error</h2>
                    <p className="error-message">{error}</p>
                    <a href="/" className="oauth-button">Back to Home</a>
                </div>
            </div>
        );
    }

    return (
        <div className="oauth-container">
            <div className="oauth-card">
                <div className="loading-spinner"></div>
                <h2>Redirecting to OAuth Server...</h2>
                <p>You will be redirected to login with UserSpice OAuth.</p>
                <p className="hint">If you are not redirected automatically,
                    please check your browser's popup blocker.</p>
            </div>
        </div>
    );
}

export default OAuthRequest;
